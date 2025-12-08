# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../tiny-sha/src

TARGET = hmac_test

SRC = tiny_hmac.c ../tiny-sha/src/tiny_sha.c hmac_test.c
OBJ = $(notdir $(SRC:.c=.o))   # put all .o files in current dir

all: $(TARGET)

# Build the executable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Compile .c into .o in current directory
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean objects and executable
clean:
ifeq ($(OS),Windows_NT)
	del /Q $(OBJ) $(TARGET).exe
else
	rm -f $(OBJ) $(TARGET)
endif

.PHONY: all clean
