APP_NAME=porthunter
CMD_PATH=./cmd/portscanner
INSTALL_PATH=/usr/local/bin

.PHONY: build run install uninstall clean tidy

build:
	go build -o $(APP_NAME) $(CMD_PATH)

run:
	go run $(CMD_PATH) $(ARGS)

install: build
	go mod tidy
	go build -o $(APP_NAME) $(CMD_PATH)
	sudo mv $(APP_NAME) $(INSTALL_PATH)/$(APP_NAME)
	@echo "$(APP_NAME) installed successfully in $(INSTALL_PATH)"

uninstall:
	sudo rm -f $(INSTALL_PATH)/$(APP_NAME)
	@echo "$(APP_NAME) removed from system"

clean:
	rm -f $(APP_NAME)

tidy:
	go mod tidy