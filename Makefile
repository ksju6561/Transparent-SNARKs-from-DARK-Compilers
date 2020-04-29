CC=gcc
CFLAGS := -g -lm -lcrypto -lgmp

SOURCE_DIR = source/

TARGET_SETUP = PC_Setup
TARGET_COMMIT = PC_Commit
TARGET_PROVER_EVAL = PC_PROVER_EVAL
TARGET_VERIFIER_EVAL = PC_VERIFIER_EVAL

all: $(TARGET_SETUP) $(TARGET_COMMIT) $(TARGET_PROVER_EVAL) $(TARGET_VERIFIER_EVAL)

clean:
	rm -f *.a *.o $(TARGET_SETUP) $(TARGET_COMMIT) $(TARGET_PROVER_EVAL) $(TARGET_VERIFIER_EVAL) Txt/proof.txt

clean_all:
	rm -f *.a *.o $(TARGET_SETUP) $(TARGET_COMMIT) $(TARGET_PROVER_EVAL) $(TARGET_VERIFIER_EVAL) Txt/commit.txt Txt/pp.txt  Txt/proof.txt

$(TARGET_SETUP): $(SOURCE_DIR)setup.c 
	$(CC) -o $@ $(SOURCE_DIR)setup.c $(SOURCE_DIR)util.c $(SOURCE_DIR)codeTimer.c $(CFLAGS)

$(TARGET_COMMIT): $(SOURCE_DIR)commit.c 
	$(CC) -o $@ $(SOURCE_DIR)commit.c $(SOURCE_DIR)util.c $(SOURCE_DIR)codeTimer.c $(CFLAGS)

$(TARGET_PROVER_EVAL): $(SOURCE_DIR)eval_prover.c 
	$(CC) -o $@ $(SOURCE_DIR)eval_prover.c $(SOURCE_DIR)util.c $(SOURCE_DIR)codeTimer.c $(SOURCE_DIR)prime_table.c $(SOURCE_DIR)poe.c $(CFLAGS)

$(TARGET_VERIFIER_EVAL): $(SOURCE_DIR)eval_verifier.c 
	$(CC) -o $@ $(SOURCE_DIR)eval_verifier.c $(SOURCE_DIR)util.c $(SOURCE_DIR)codeTimer.c $(SOURCE_DIR)prime_table.c $(SOURCE_DIR)poe.c $(CFLAGS)
