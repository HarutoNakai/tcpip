import os
import struct
import fcntl
import threading
import socket


# LinuxでTAPデバイスを作るための固定の暗号（定数）
TUNSETIFF = 0x400454ca
IFF_TAP = 0x0002    # L2のTAPデバイスを指定
IFF_NO_PI = 0x1000  # 余計なパケット情報を付けない設定


my_mac = bytes.fromhex("191945450721")
my_ip = socket.inet_aton("192.168.0.2")

def create_tap_device(dev_name="tap0"):
    # 1. 魔法の工場を開く
    fd = os.open("/dev/net/tun", os.O_RDWR)
    
    # 2. OSに渡す注文書（構造体）を作成
    ifr = struct.pack('16sH', dev_name.encode('utf-8'), IFF_TAP | IFF_NO_PI)
    
    # 3. カーネルに直接命令を送る！
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    
    print(f"仮想デバイス '{dev_name}' と接続しました！")
    return fd
# メインプログラムの最初でこれを呼び出せばOKです！
tap_fd = create_tap_device("tap0")

def monitor_data():
    while True:
        # パケットを受信するまでここで待機（ブロック）する
        pac = os.read(tap_fd, 2048)
        
        # 先頭14バイトを解析
        dest_mac, src_mac, ethertype = struct.unpack("!6s6sH", pac[:14])
        
        # MACアドレスを読める形に（送信元MACも同じように変換できますね）
        mac_parts = [f"{b:02x}" for b in dest_mac]
        dest_mac_str = ":".join(mac_parts)
        

        # プロトコルの振り分け
        if ethertype == 0x0806:
            print(f"ARPパケットを受信！ (Type: {ethertype:04x})")
            # 次のステップ: ここでARP専用関数へデータを渡す
            arp(pac)
        elif ethertype == 0x0800:
            print(f"IPパケットを受信！ (Type: {ethertype:04x})")
            # 次のステップ: ここでIP専用関数へデータを渡す
            ip(pac)
        else:
            print(f"その他のプロトコル: {ethertype:04x}")

def arp(pac):
    arp_data = pac[14:]
    hw_type, proto_type, hw_len, ip_len, opcode, src_mac, src_ip, dst_mac, dst_ip = struct.unpack("!HHBBH6s4s6s4s", arp_data)
    print(f"ARPの中身を解剖！ オペレーションコード(Opcode): {opcode}")

    arp_body = struct.pack("!HHBBH6s4s6s4s",
        0x0001,      # ハードウェアタイプ (Ethernetは1)
        0x0800,      # プロトコルタイプ (IPv4は0x0800)
        6,           # MACアドレスの長さ
        4,           # IPアドレスの長さ
        2,           # ★ここが Opcode! (2 = Reply)
        my_mac,      # 送信元MAC (自分のMAC)
        my_ip,       # 送信元IP (自分のIP)
        src_mac,     # 宛先MAC (さっき受信したパケットの送信元＝LinuxのMAC)
        src_ip       # 宛先IP (さっき受信したパケットの送信元＝LinuxのIP)
    )

    eth_header = struct.pack("!6s6sH",
    src_mac,     # 宛先 (LinuxのMAC)
    my_mac,      # 送信元 (自分のMAC)
    0x0806       # Ethernetタイプ (0x0806 = ARP)
    )

    reply_packet = eth_header + arp_body
    os.write(tap_fd, reply_packet)
    print("返信しました！")

def ip(pac):
    # 14バイト目から20バイト分がIPヘッダ
    ip_header = pac[14:14+20]
    v_ihl, tos, total_len, id, flags_off, ttl, protocol, checksum, src_ip, dst_ip = struct.unpack("!BBHHHBBH4s4s", ip_header)
    print(f"IPパケットを受信！ プロトコル番号: {protocol}")

    if protocol == 1:
        #icmpに処理させる
        icmp(pac)


def icmp(pac):
    # 1. まず、受信したパケットの先頭14バイト（Ethernetヘッダ）から、最新のMACアドレスを抽出！
    dest_mac, src_mac, ethertype = struct.unpack("!6s6sH", pac[:14])

    # 2. 14バイト目から20バイト分がIPヘッダ
    ip_header_recv = pac[14:34]
    v_ihl, tos, total_len, id, flags_off, ttl, protocol, ip_checksum, src_ip, dst_ip = struct.unpack("!BBHHHBBH4s4s", ip_header_recv)

    # 3. ICMPヘッダとペイロードの切り出し
    icmp_header = pac[34:42]
    icmp_payload = pac[42:]
    type, code, checksum, identifier, sequence_number = struct.unpack("!BBHHH", icmp_header)

    # --- こっから先は返信ステップ ---

    # 1. 仮のICMPヘッダとペイロードを合体させてチェックサムを計算
    dummy_icmp = struct.pack("!BBHHH", 0, 0, 0, identifier, sequence_number) + icmp_payload
    new_checksum = calc_checksum(dummy_icmp)

    # 2. 正しいチェックサムを入れてICMPヘッダを作り直す
    icmp_header = struct.pack("!BBHHH", 0, 0, new_checksum, identifier, sequence_number)

    # 3. IPヘッダを作る (送信元と宛先を入れ替える！チェックサムはそのまま再利用の裏技✨)
    ip_header = struct.pack("!BBHHHBBH4s4s", v_ihl, tos, total_len, id, flags_off, ttl, protocol, ip_checksum, dst_ip, src_ip)

    # 4. Ethernetヘッダを作る (!6s6sH) ★ここが今回の最大の修正ポイント！★
    eth_header = struct.pack("!6s6sH",
                            src_mac, # 宛先MAC (さっき取り出した、今のLinuxの最新MACアドレス)
                            my_mac,  # 送信元MAC (あなたのMAC)
                            0x0800)  # IPv4 (IPパケット)

    # 5. ガッチャンコして送信！
    reply_packet = eth_header + ip_header + icmp_header + icmp_payload
    os.write(tap_fd, reply_packet)
    print("ICMP（Ping）のお返事を送信しました！！！🚀")
def calc_checksum(data):
    # 1. データ長が奇数なら、最後に 0x00 (1バイトのゼロ) を足して偶数にする
    if len(data) % 2 != 0:
        data = data + b'\x00'

    total = 0
    # 2. 2バイト(16ビット)ずつ取り出して足し算
    for i in range(0, len(data), 2):
        # !H で2バイトの数字として解釈し、[0]でタプルから数字だけを取り出す
        word = struct.unpack("!H", data[i:i+2])[0]
        total = total + word

    # 3. 桁あふれ(キャリー)の処理: 16ビット(0xFFFF)を超えた分を下に足し戻す
    # totalを右に16ビットずらして(>>16)はみ出た部分があれば、ループで足し戻す
    while (total >> 16) > 0:
        total = (total & 0xFFFF) + (total >> 16)

    # 4. 最後にビットを反転(1の補数)させる
    # Pythonでは ~ (チルダ) で反転し、0xFFFFで下位16ビットだけを残す
    checksum = ~total & 0xFFFF

    return checksum





# スレッドを起動
thread1 = threading.Thread(target=monitor_data)
thread1.daemon = True # メインプログラム終了時にスレッドも終わるようにする設定
thread1.start()

# メインスレッドは別の作業ができる（今回はテストのため無限ループで待機）
while True:
    pass