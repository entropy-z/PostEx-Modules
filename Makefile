SRC_DIR = .
BUILD_DIR = Bin

# Find all .cc files in SRC_DIR and its subfolders
SOURCES = $(shell find $(SRC_DIR) -type f -name '*.cc')

# Exceptions list (both in root and subdirectories)
EXCEPTIONS = PatchExit.cc Utils.cc IAT.cc Hwbp.cc

# Create full paths to exclude
EXCLUDE_PATHS = $(foreach exc,$(EXCEPTIONS),$(SRC_DIR)/$(exc)) \
                $(foreach dir,Hooks Dotnet COM PE Shellcode,$(addprefix $(SRC_DIR)/$(dir)/,$(EXCEPTIONS)))

# Filter out exceptions
FILTERED_SOURCES = $(filter-out $(EXCLUDE_PATHS),$(SOURCES))

CC = x86_64-w64-mingw32-g++
CFLAGS = -I$(INCLUDES_DIR) -w -Os -DBOF -std=c++23 -I Include -I .

all: x64 

x64: $(FILTERED_SOURCES:$(SRC_DIR)/%.cc=$(BUILD_DIR)/%.x64.o)
# x32: $(FILTERED_SOURCES:$(SRC_DIR)/%.cc=$(BUILD_DIR)/x32/%.o)

$(BUILD_DIR)/%.x64.o: $(SRC_DIR)/%.cc
	@echo "[+] Compiling $< for x64..."
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -m64 -Wno-attributes -o $@ -c $<

# $(BUILD_DIR)/x32/%.o: $(SRC_DIR)/%.cc
# 	@echo "[+] Compiling $< for x32..."
# 	@mkdir -p $(@D)
# 	$(CC) $(CFLAGS) -m32 -Wno-attributes -o $@ -c $<

clean:
	@echo "Cleaning up build artifacts..."
	rm -rf $(BUILD_DIR)
	@echo "Cleanup complete!"