
function Get-Netstat
{
    $output = netstat -an -p tcp | grep LISTEN

    # macOS netstat:
    # Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
    # tcp46      0      0  *.8080                 *.*                    LISTEN
    # tcp4       0      0  127.0.0.1.631          *.*                    LISTEN

    foreach ($line in $output) {
        $line = $line -Replace '^\s+', ''
        $line = $line -Split '\s+'
        $Protocol = $line[0]
        $LocalAddress = $line[3]
        $ForeignAddress = $line[4]
        $State = $line[5]

        $LocalPort = $($LocalAddress -Split '\.')[-1] # macOS uses '.' separator for port

        New-Object -TypeName PSObject -Property @{
            Protocol = $Protocol
            LocalAddress = $LocalAddress
            LocalPort = $LocalPort
            ForeignAddress = $ForeignAddress
            State = $State
        }
    }
}
