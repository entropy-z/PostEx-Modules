ARCH ?= x64
CXX  := x86_64-w64-mingw32-g++
CXXFLAGS := -Os -std=c++20 -fno-exceptions -nostdlib -Wall -IInclude -w -fpermissive -DWSMAN_API_VERSION_1_1


SRC  := Source/Main.cc
OBJ  := jump-winrm.$(ARCH).o

all: $(OBJ)

$(OBJ): $(SRC)
	$(CXX) $(CXXFLAGS) -c $(SRC) -o Dist/$@

clean:
	rm -f jump-winrm.*.o
