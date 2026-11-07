"""Split scalar/escape bytes, wide/combining text, alternate screen, no final newline."""
import os
import time
for byte in "界😀e\u0301\x1b[?1049hALT\x1b[?1049lTAIL".encode():
    os.write(1, bytes([byte]))
    time.sleep(0.002)
