setx DISPLAY 0
setx GPU_MAX_ALLOC_PERCENT 100
setx GPU_USE_SYNC_OBJECTS 1

sgminer --algorithm neoscrypt --worksize 128 --thread-concurrency 200 -I 8 -o stratum+tcp://coinotron.com:3337 -u cqtenq.1 -p 110
