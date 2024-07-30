# Makefile
CC = gcc
CFLAGS = -Iinclude -Wall
CFLAGS_RELEASE = -O3 -DNDEBUG

DEPS = include/interface.h

#目标文件
SRC = $(wildcard src/*.c)
OBJ = $(patsubst %.c, %.o, $(SRC))



# 运行并生成日志文件
# make 2>&1 | tee build.log

#可执行文件
TARGET = project

#默认目标
all: release

debug: CFLAGS += -g
debug: $(TARGET)

release: CFLAGS += $(CFLAGS_RELEASE)
release: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)


.PHONY: clean bulid
clean:
	del project.exe, src\*.o

