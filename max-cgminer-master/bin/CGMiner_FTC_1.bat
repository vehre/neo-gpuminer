setx DISPLAY 0
setx GPU_MAX_ALLOC_PERCENT 100
setx GPU_USE_SYNC_OBJECTS 1

rem # cgminer --neoscrypt --worksize 128 --thread-concurrency 200  -o http://prometheus.phoenixcoin.org:19555 -u lizhi -p 12345
rem # cgminer --neoscrypt --worksize 128 --thread-concurrency 200  -o http://pool.ftc-c.com:19327 -u lizhi -p 12345
rem #ok cgminer --neoscrypt --worksize 128 --thread-concurrency 200  -o http://pool.ftc-c.com:19328 -u lizhi -p 12345
cgminer --neoscrypt --worksize 128 --thread-concurrency 200  -o stratum+tcp://coinotron.com:3337 -u cqtenq.1 -p 110
