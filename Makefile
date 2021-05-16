fuzz-build-record-layer: fuzz-prepare
	go-fuzz-build -tags gofuzz -func FuzzRecordLayer
fuzz-run-record-layer:
	go-fuzz -bin dtls-fuzz.zip -workdir fuzz
fuzz-prepare:
	@GO111MODULE=on go mod vendor
prepare-liboqs:
	# Setup liboqs
	cd $HOME/Documents && git clone -b main https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	mkdir build && cd build
	cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
	sudo ninja install

	# Set up liboqs-go
	cd $HOME/Documents && git clone https://github.com/open-quantum-safe/liboqs-go
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
	sed -i 's/C:\/Users\/vsoft\/GitHub\/liboqs\/build\/include/\/usr\/local\/include/' liboqs-go/.config/liboqs.pc
	sed -i 's/C:\/Users\/vsoft\/GitHub\/liboqs\/build\/lib\/Debug/\/usr\/local\/lib/' liboqs-go/.config/liboqs.pc
	export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$HOME/liboqs-go/.config
