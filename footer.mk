

PKG_BASE ?= $(CURDIR)/../../..
BASE=$(realpath $(PKG_BASE))

NF_TOOLS ?= $(BASE)/compiler/lib

# allow object files to be declared this way also
OBJS=${SRC:.c=.o}
$(TARGET): $(OBJS)
TARGETS ?= $(TARGET)

all: $(TARGETS)

$(START): nf2.s
	$(SPE_AS)  -O3 -march=sp $< -o $@

nf2.s: nf2.S
	$(SPE_CPP) $(EXTRA_DEFINES) $< $@

########################################################
$(TARGETS): $(FUNC_LIB) $(START) $(MATH) $(FLOATING) $(EXTRA_LIB) $(ULIBS) $(NEW_ALLOC)
	$(SPE_LD) $(filter %.o,$^) $(NEW_ALLOC) $(ULIBS) $(LDFLAGS) $(EXTRA_LIB) -o $@ --print-map  > $@.map
	egrep "^ *0x0000000004" $@.map |grep -v PROVIDE > $@.static

############################################################# 
#############################################################

clean:
	rm -f $(TARGETS) $(TARGETS:=.map) $(TARGETS:=.static) *.o *.s *.S debug_sched*


OBJDUMP=$(SPE_DIS)
OBJCOPY=$(SPE_PREFIX)-objcopy

embed:  mif 

rif: $(TARGETS:=.instr.rif) $(TARGETS:=.data.rif) $(TARGETS:=.instr.mif) $(TARGETS:=.data.mif)

%.instr.rif: %.instr.mif
	mif2rif $< $@ >&/dev/null; [ -s $@ ]

%.data.rif: %.data.mif
	mif2rif $< $@ >&/dev/null; [ -s $@ ]

######################## Mif creation  ##########################

mif: $(TARGETS:=.instr.mif) $(TARGETS:=.data.mif)

%.dmp : %
	$(OBJDUMP) -D -z $< | awk '/^$$/{next;}$$2~"<"{next;}{print $0}' | cut -f 1,2 | tr -d ":" > $*.dmp

%.data.mif: %.dmp
	awk 'BEGIN{mp=0;printf("WIDTH=32;\nDEPTH=65536;\n\nADDRESS_RADIX=HEX;\nDATA_RADIX=HEX;\n\nCONTENT BEGIN\n\n");} \
/data/{mp=1;next;}/bss/{mp=1;next;}/eh_/{mp=1;next;}/section/{mp=0;next;} \
(mp==1){v=strtonum("0x"$$1)/4-0x1010000;printf("%08x : %s;\n",v,$$2);} \
END {print "END;";}' \
 $*.dmp > $@

%.instr.mif: %.dmp
	awk 'BEGIN{mp=0;printf("WIDTH=32;\nDEPTH=65536;\n\nADDRESS_RADIX=HEX;\nDATA_RADIX=HEX;\n\nCONTENT BEGIN\n\n");} \
/text/{mp=1;next;}/section/{mp=0;next;} \
(mp==1){v=and(strtonum("0x"$$1),262143)/4;printf("%08x : %s;\n",v,$$2);} \
END {print "END;";}' \
 $*.dmp > $@


embed_clean:
	rm -f $(TARGETS:=.instr.rif) $(TARGETS:=.data.rif) $(TARGETS:=.instr.mif) $(TARGETS:=.data.mif)
	rm -f instr.rif data.rif *.t *.rif *.mif *.raw debug_sched*.txt 

redo: clean all embed



