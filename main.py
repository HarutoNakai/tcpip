# =====================================================================
#  Project: Toy TCP/IP Stack from Scratch
#  File: main.py
#  Author: Haruto Nakai (DJANGØ)
#  Date: 2026-05-11
#
#  Description:
#    LinuxのTAPデバイス(L2)を利用し、Pythonでゼロから構築した
#    ネットワークプロトコルスタック。
#    ハンドシェイクからHTTPレスポンスまで、バイナリレベルで自力実装。
#
#  Supported Protocols:
#    - Layer 2: Ethernet, ARP (Request/Reply)
#    - Layer 3: IPv4, ICMP (Echo Reply / Ping response)
#    - Layer 4: TCP (3-way handshake, PSH/ACK flow)
#    - Layer 7: HTTP (Basic GET Response)
#
#  Usage:
#    sudo python3 main.py
# =====================================================================


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
    
    print("Linux側にIPアドレスを設定して、電源をONにします...⚡")
    os.system(f"ip addr add 192.168.0.1/24 dev {dev_name}")
    os.system(f"ip link set dev {dev_name} up")

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

    #ここでIPプロトコル振り分け
    if protocol == 1:
        #icmpに処理させる
        icmp(pac)
    elif protocol == 6:
        tcp(pac)


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


def tcp(pac):
    # ★追加：IPヘッダからIPアドレスをもう一度取り出しておく
    ip_header_recv = pac[14:34]
    v_ihl, tos, total_len, id, flags_off, ttl, protocol, ip_checksum, src_ip, dst_ip = struct.unpack("!BBHHHBBH4s4s", ip_header_recv)

    # 34バイト目から20バイト分がTCPヘッダ
    tcp_header = pac[34:54]
    src_port, dst_port, seq_num, ack_num, offset, flags, window, checksum, urgent_ptr = struct.unpack("!HHIIBBHHH", tcp_header)
    print(f"TCPパケットが来たよ! Port: {src_port} -> {dst_port}")

    # もし相手のフラグに SYN (2) が含まれていたら
    if (flags & 2) != 0:
        print("相手からSYNが来た！🤝")

        # 相手からの src_port と dst_port を逆にして組み立てる！
        dummy_tcp_header = struct.pack("!HHIIBBHHH",
            dst_port,     # 1. 送信元ポート (自分のポート)
            src_port,     # 2. 宛先ポート (Linux側のポート)
            1000,         # 3. シーケンス番号
            seq_num + 1,  # 4. 確認応答番号 (ACK)
            80,           # 5. オフセット
            18,           # 6. フラグ (SYN + ACK)
            8192,         # 7. ウィンドウサイズ
            0,            # 8. チェックサム (今は仮の0)
            0             # 9. 緊急ポインタ
        )

        pseudo_header = struct.pack("!4s4sBBH",
            dst_ip,
            src_ip,
            0,
            6,
            20
        )

        # 1. 擬似ヘッダと仮のTCPヘッダをガッチャンコ！ (順番は 擬似 -> TCP)
        check_data = pseudo_header + dummy_tcp_header

        # 2. 正しいチェックサムを弾き出す！
        tcp_checksum = calc_checksum(check_data)

        # 3. 正しいチェックサムを組み込んで、本物のTCPヘッダを作り直す！
        tcp_header_reply = struct.pack("!HHIIBBHHH",
            dst_port,
            src_port,
            1000,
            seq_num + 1,
            80,
            18,
            8192,
            tcp_checksum,  # ★本物のチェックサム！
            0
        )

        print("SYN-ACKのTCPヘッダが完成しました！！✨")
       # 4. IPヘッダを作り直す！（裏技卒業✨）
        # 私たちが作ったのは IP(20) + TCP(20) なので、全長(total_len)は「40」！
        dummy_ip_header = struct.pack("!BBHHHBBH4s4s", 
            v_ihl, tos, 40, id, flags_off, ttl, protocol, 0, dst_ip, src_ip) # チェックサムは仮の0

        # IPヘッダ専用のチェックサムを計算！
        new_ip_checksum = calc_checksum(dummy_ip_header)

        # 正しいチェックサムを入れて本物のIPヘッダを完成させる！
        ip_header = struct.pack("!BBHHHBBH4s4s", 
            v_ihl, tos, 40, id, flags_off, ttl, protocol, new_ip_checksum, dst_ip, src_ip)
        
        # 5. Ethernetヘッダを作る (送信先MACは、パケットを受信した時の先頭14バイトから取る)
        dest_mac_recv, src_mac_recv, ethertype = struct.unpack("!6s6sH", pac[:14])
        eth_header = struct.pack("!6s6sH",
                                src_mac_recv,  # 宛先MAC (Linuxの最新MACアドレス)
                                my_mac,        # 送信元MAC (あなたのMAC)
                                0x0800)        # IPv4 (IPパケット)

        # 6. 全部ガッチャンコ！！！ (Ethernet -> IP -> TCP の順番が命！)
        reply_packet = eth_header + ip_header + tcp_header_reply
        
        # 7. 今度こそ本当の送信！！！🚀
        os.write(tap_fd, reply_packet)
        print("SYN-ACKを返信したぜ！！！✨")

    elif (flags & 24) == 24:
        print("データ(ペイロード)付きのパケットが来た！📦")
        dest_mac_recv, src_mac_recv, ethertype = struct.unpack("!6s6sH", pac[:14])
        # Q2: TCPヘッダの本当の長さを逆算する！
        # 受信した offset(例:80) を >> 4 で右にズラして「5」に戻す。
        # それは「4バイト単位」の数字なので、元に戻すために掛ける数字は？
        tcp_header_len = (offset >> 4) * 4

        # Q3: ペイロード(中身)を切り出す！
        # Ethernet(14) + IP(20) + TCPの長さ の合計が、データの開始地点！
        payload_start = 14 + 20 + tcp_header_len
        payload = pac[payload_start:]

        # データの中身が空じゃなければ、文字として表示してみる！
        if len(payload) > 0:
            print("【受信したデータの中身】")
            print("--------------------------------------------------")
            print(payload.decode('utf-8', errors='ignore'))
            print("--------------------------------------------------")

            # ==== ▼ここから追加！ブラウザにWebページを返信しよう！▼ ====
            print("Webページを生成して返信します！🌍")

            # 1. 送り返すWebページ（HTTPレスポンス）の作成
            # HTTPのルール：「ヘッダ」と「ボディ」の間は必ず改行2つ(\r\n\r\n)空ける！
            http_body = "<html><body><h1>Hello TCP/IP! You are Success!</h1></body></html>"
            http_response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(http_body)}\r\n\r\n{http_body}"
            reply_payload = http_response.encode('utf-8')

            # 2. シーケンス番号とACK番号の計算（TCP最大のパズル🧩）
            new_seq = ack_num                  # 相手が「次はこの番号から送って」と言ってきた番号
            new_ack = seq_num + len(payload)   # 「あなたのデータ〇〇バイト分、確かに受け取ったよ」のサイン

            # 3. 仮のTCPヘッダ（フラグは PSH + ACK ＝ 24）
            dummy_tcp = struct.pack("!HHIIBBHHH",
                dst_port, src_port, new_seq, new_ack, 80, 24, 8192, 0, 0
            )

            # 4. 擬似ヘッダ（★注意：今回は荷物がある分、全長が長くなる！）
            tcp_total_len = 20 + len(reply_payload)
            pseudo_header = struct.pack("!4s4sBBH", dst_ip, src_ip, 0, 6, tcp_total_len)

            # 5. チェックサム計算と本物TCPヘッダ作成
            # 今回は荷物(reply_payload)も一緒にチェックサムの計算機に入れる！
            tcp_checksum = calc_checksum(pseudo_header + dummy_tcp + reply_payload)
            real_tcp = struct.pack("!HHIIBBHHH",
                dst_port, src_port, new_seq, new_ack, 80, 24, 8192, tcp_checksum, 0
            )

            # 6. IPヘッダ作成 (★ここも荷物がある分、全長が長くなる！)
            ip_total_len = 20 + 20 + len(reply_payload)
            dummy_ip = struct.pack("!BBHHHBBH4s4s",
                v_ihl, tos, ip_total_len, id, flags_off, ttl, protocol, 0, dst_ip, src_ip
            )
            ip_checksum = calc_checksum(dummy_ip)
            real_ip = struct.pack("!BBHHHBBH4s4s",
                v_ihl, tos, ip_total_len, id, flags_off, ttl, protocol, ip_checksum, dst_ip, src_ip
            )

            # 7. Ethernetヘッダ作成
            eth_header = struct.pack("!6s6sH", src_mac_recv, my_mac, 0x0800)

            # 8. 全て合体して送信！！！ (ヘッダ3兄弟 ＋ Webページデータ)
            final_packet = eth_header + real_ip + real_tcp + reply_payload
            os.write(tap_fd, final_packet)
            print("ブラウザにWebページを送信完了！！！🚀")

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