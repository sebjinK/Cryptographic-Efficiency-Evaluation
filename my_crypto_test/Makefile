#---------------------------------------------------------------------------#
#  examples/my_crypto_test/Makefile
#---------------------------------------------------------------------------#

CONTIKI_PROJECT = my_crypto_test
CONTIKI         = ../..
all: $(CONTIKI_PROJECT)
# 1) Tell the compiler to pick up your project-conf.h
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\" -Iascon -Ipresent -Ispeck -Itinyaes

# # 2) Force the null-netstack to be *built* and linked
# MAKE_NET    = nullnet
# MAKE_MAC    = nullmac
# MAKE_RDC    = nullrdc
# MAKE_FRAMER = nullframer
# MAKE_RADIO  = cc2420

# CFLAGS += -Os -DNDEBUG

# 4) Your crypto sources:
PROJECT_SOURCEFILES += ascon/ascon.c speck/speck.c present/present.c tinyaes/aes.c
MODULES += os/services/simple-energest
$(shell mkdir -p build/$(TARGET)/obj/ascon build/$(TARGET)/obj/speck \
                build/$(TARGET)/obj/present build/$(TARGET)/obj/tinyaes)

# 5) Finally pull in Contiki’s build rules
include $(CONTIKI)/Makefile.include
