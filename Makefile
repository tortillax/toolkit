BINARY_DIR := bin
CMD_DIR := cmd
DATA_DIR := data

TARGETS := $(notdir $(wildcard $(CMD_DIR)/*))

.PHONY: all clean $(TARGETS)

all: $(TARGETS)

$(TARGETS):
	go build -o $(BINARY_DIR)/$@ ./$(CMD_DIR)/$@

clean:
	rm -rf $(BINARY_DIR)
	rm -rf $(DATA_DIR)

test:
	go test -v ./...

ca-init:
	mkdir $(DATA_DIR)
	cd $(DATA_DIR) && ../$(BINARY_DIR)/ca