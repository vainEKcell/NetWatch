# 裸 STUN 探测：验证网络路径是否可达（与 NetWatch 代码无关的独立实现）
$targets = @('stun.qq.com', 'stun.miwifi.com', 'stun.cloudflare.com')
foreach ($t in $targets) {
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = 4000
        $addrs = [System.Net.Dns]::GetHostAddresses($t)
        $v4 = $addrs | Where-Object AddressFamily -eq 'InterNetwork' | Select-Object -First 1
        if (-not $v4) { Write-Output "$t : DNS 无 A 记录"; $udp.Close(); continue }

        $msg = New-Object byte[] 20
        $msg[0] = 0; $msg[1] = 1
        $msg[4] = 0x21; $msg[5] = 0x12; $msg[6] = 0xA4; $msg[7] = 0x42
        $rnd = New-Object System.Random
        for ($i = 8; $i -lt 20; $i++) { $msg[$i] = $rnd.Next(256) }
        $tx = $msg[8..19]

        $ep = New-Object System.Net.IPEndPoint($v4, 3478)
        $udp.Connect($ep)
        [void]$udp.Send($msg, 20)
        try {
            $any = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $res = $udp.Receive([ref]$any)
            if ($res.Length -ge 20 -and $res[0] -eq 0 -and $res[1] -eq 1) {
                # 走 TLV 找 XOR-MAPPED-ADDRESS (0x0020)
                $len = ($res[2] -shl 8) -bor $res[3]
                $pos = 20; $end = [Math]::Min(20 + $len, $res.Length); $found = $false
                while ($pos + 4 -le $end) {
                    $type = ($res[$pos] -shl 8) -bor $res[$pos + 1]
                    $alen = ($res[$pos + 2] -shl 8) -bor $res[$pos + 3]
                    if ($type -eq 0x20 -and $alen -ge 8) {
                        $p = $pos + 4
                        $rawPort = ($res[$p+2] -shl 8) -bor $res[$p+3]
                        $port = $rawPort -bxor 0x2112
                        $a = @($res[$p+4] -bxor 0x21, $res[$p+5] -bxor 0x12, $res[$p+6] -bxor 0xA4, $res[$p+7] -bxor 0x42)
                        $ip = ($a | ForEach-Object { $_ }) -join '.'
                        Write-Output "$t ($v4) : XOR-MAPPED $ip : $port"
                        $found = $true
                        break
                    }
                    $pos += 4 + (($alen + 3) -band -4)
                }
                if (-not $found) { Write-Output "$t : 响应但未含 XOR-MAPPED (len=$len)" }
            } else { Write-Output "$t : 非成功响应" }
        } catch {
            Write-Output "$t ($v4) : 4 秒无响应（UDP 被拦截或服务器不可达）"
        }
        $udp.Close()
    } catch {
        Write-Output "$t : 异常 $($_.Exception.Message)"
    }
}
