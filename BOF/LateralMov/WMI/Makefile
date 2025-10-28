ARCH ?= x64
CXX  := x86_64-w64-mingw32-g++
CXXFLAGS := -Os -std=c++20 -fno-exceptions -nostdlib -IInclude -w -fpermissive


SRC  := Source/Main.cc
OBJ  := jump-wmi.$(ARCH).o

all: $(OBJ)

$(OBJ): $(SRC)
	$(CXX) $(CXXFLAGS) -c $(SRC) -o Dist/$@

clean:
	rm -f jump-wmi.*.o