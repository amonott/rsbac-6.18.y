#
# Main Makefile for the Rule Set Based Access Control subsystem.
#
# Author and (c) 1999-2013 Amon Ott <ao@rsbac.org>

obj-y     := help/ data_structures/ adf/
obj-m     := adf/

clean:	Makefile
	rm -f `find . -name modules.builtin -o -name modules.order -name '*.o' -o -name '*.o.cmd' -o -name '*.ko' -o -name '*.ko.cmd' -print`

