ARCH ?= x64
CXX  := x86_64-w64-mingw32-g++
CXXFLAGS := -Os -std=c++20 -fno-exceptions -nostdlib -Wall -IInclude -w -fpermissive -DWSMAN_API_VERSION_1_1

SRC  := Source/mmc_execshell.cc
OBJ  := jump-dcom_mmc_execshell.$(ARCH).o

all: $(OBJ)

$(OBJ): $(SRC)
	$(CXX) $(CXXFLAGS) -c $(SRC) -o Dist/$@

clean:
	rm -f jump-dcom_mmc_execshell.*.o