# Welcome to my paper evaluating the energy effiency of different cryptographic algorithms

Attached is both my pdf paper and the the 5 cryptographic algorithms I set up. 

These algorithms implementations were adapted from these 5 sources:

ASCON: https://github.com/haskucy/ascon_implementation_C
SPECK: https://github.com/jameswmccarty/SPECK-cipher
PRESENT: https://github.com/Pepton21/present-cipher
Tiny-AES-128: https://github.com/kokke/tiny-AES-c

These algorithms, were taken and adapted to be used in a test within the IoT Simulator Contiki/Cooja.
To implement them yourself, feel free to first install WSL/Ubuntu and then Contiki/Cooja by watching 
this video: https://youtu.be/zfA9BINRvVk?si=FrnRx2u9KVjKCH2L

Link to gist within the video (easier to copy + paste this after you've gotten to 7:58 in the video): https://gist.github.com/ekawahyu/73ac940f8e91dd6e34cd8cbb23e83e17/raw/c3c3047540873b0b1f6dff1b86ad7c5f927f66d9/msp430-gcc-4.7.0-build.sh

use: ```wget https://gist.github.com/ekawahyu/73ac940f8e91dd6e34cd8cbb23e83e17/raw/c3c3047540873b0b1f6dff1b86ad7c5f927f66d9/msp430-gcc-4.7.0-build.sh```

Then go ahead and copying my_crypto_test into your contiki-ng/examples folder. Try running as soon as you're done.