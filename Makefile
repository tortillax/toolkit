.SILENT:

BINARY_DIR := bin
INSTALL_DIR := /usr/local/bin
CMD_DIR := cmd
DATA_DIR := data
PREFIX := tk

TARGETS := $(notdir $(wildcard $(CMD_DIR)/*))

.PHONY: all $(TARGETS) clean test install 

all: $(TARGETS)

$(TARGETS):
	go build -o $(BINARY_DIR)/$@ ./$(CMD_DIR)/$@
	@echo ls $(BINARY_DIR)
	@ls $(BINARY_DIR)

clean:
	rm -rf $(BINARY_DIR)
	rm -rf $(DATA_DIR)

	@echo done
test:
	go test -v ./...

install:
	for f in $(BINARY_DIR)/*; do \
		echo "installing $(PREFIX)-$$(basename $$f)"; \
		cp $$f $(INSTALL_DIR)/$(PREFIX)-$$(basename $$f); \
	done

uninstall:
	rm $(INSTALL_DIR)/tk-*
	@echo done