gcc --no-pie main.cpp curve25519-donna.cpp sosemanuk.cpp sha256.cpp args.cpp thpool.c -o e_esxi.out -pthread -lstdc++
strip e_esxi.out
