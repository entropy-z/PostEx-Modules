INCLUDE_DIR := Include
SOURCE_DIR := Source
OUTPUT_DIR := Bin

ARCH ?= x64

CXX := x86_64-w64-mingw32-g++
CXXFLAGS := -std=c++20 -fpermissive -w -Wextra -I$(INCLUDE_DIR) -c

OBJECTS := \
	$(OUTPUT_DIR)/az-prt-token.$(ARCH).o

all: $(OBJECTS)


$(OUTPUT_DIR)/az-prt-token.$(ARCH).o: $(SOURCE_DIR)/Main.cc | $(OUTPUT_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

clean:
	rm -f $(OUTPUT_DIR)/*.o

.PHONY: all clean