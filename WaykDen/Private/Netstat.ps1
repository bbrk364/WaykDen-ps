
function Get-Netstat
{
    if ($IsLinux) {
        $output = netstat -an --tcp | grep LISTEN

        # Linux netstat:
        # Proto Recv-Q Send-Q Local Address           Foreign Address         State
        # tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN
        # tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
        # tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN

        foreach ($line in $output) {
            $line = $line -Replace '^\s+', ''
            $line = $line -Split '\s+'
            $Protocol = $line[0]
            $RecvQueue = $line[1]
            $SendQueue = $line[2]
            $LocalAddress = $line[3]
            $ForeignAddress = $line[4]
            $State = $line[5]

            $LocalPort = $($LocalAddress -Split ':')[-1] # Linux uses ':' separator for port

            New-Object -TypeName PSObject -Property @{
                Protocol = $Protocol
                RecvQueue = $RecvQueue
                SendQueue = $SendQueue
                LocalAddress = $LocalAddress
                LocalPort = $LocalPort
                ForeignAddress = $ForeignAddress
                State = $State
            }
        }
    }
    elseif ($IsMacOS) {
        $output = netstat -an -p tcp | grep LISTEN

        # macOS netstat:
        # Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
        # tcp46      0      0  *.8080                 *.*                    LISTEN
        # tcp4       0      0  127.0.0.1.631          *.*                    LISTEN

        foreach ($line in $output) {
            $line = $line -Replace '^\s+', '' # trim whitespace at the beginning of line
            $line = $line -Split '\s+' # split line by whitespace
            $Protocol = $line[0]
            $RecvQueue = $line[1]
            $SendQueue = $line[2]
            $LocalAddress = $line[3]
            $ForeignAddress = $line[4]
            $State = $line[5]

            $LocalPort = $($LocalAddress -Split '\.')[-1] # macOS uses '.' separator for port

            New-Object -TypeName PSObject -Property @{
                Protocol = $Protocol
                RecvQueue = $RecvQueue
                SendQueue = $SendQueue
                LocalAddress = $LocalAddress
                LocalPort = $LocalPort
                ForeignAddress = $ForeignAddress
                State = $State
            }
        }
    }
    else { # Windows
        
    }
}

Get-Netstat
