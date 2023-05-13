# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = QubesCTAPproxy
SOURCEDIR     = .
BUILDDIR      = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

MANDIR = /usr/share/man
install:
	for chapter in 1 8; do \
		install -d $(DESTDIR)$(MANDIR)/man$${chapter}; \
		install -t $(DESTDIR)$(MANDIR)/man$${chapter} \
			$(BUILDDIR)/man/*.$${chapter}*; \
	done

.PHONY: help install Makefile

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
