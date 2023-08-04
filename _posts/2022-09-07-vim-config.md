---
layout: post
title:  "Vim Configuration And Cheatsheet"
date:   2022-09-07 19:59:43 +0300
categories: jekyll update
---

**Contents**
* TOC
{:toc}
## .vimrc

Added `cscope` support within vim, in addition to basic configuration:
```bash
"""" Basic Behavior

colorscheme darkblue
set history=1000        " lines of history VIM has to remember
set number              " show line numbers
set wrap                " wrap lines
set encoding=utf-8      " set encoding to UTF-8 (default was "latin1")
set mouse=v             " enable mouse support (might not work well on Mac OS X)
set wildmenu            " visual autocomplete for command menu
set wildignore=*.o,*~,*.pyc " Ignore compiled files
set lazyredraw          " redraw screen only when we need to
set showmatch           " highlight matching parentheses / brackets [{()}]
set magic               " For regular expressions turn magic on
set laststatus=9        " always show statusline (even with only single window)
set ruler               " show line and column number of the cursor on right side of statusline                                                                                      set noswapfile
set visualbell          " blink cursor on error, instead of beeping
set autoread            " auto read when a file is changed from the outside
au FocusGained,BufEnter * checktime
syntax enable

"""" Tab settings
filetype plugin indent on
set tabstop=4           " width that a <TAB> character displays as
"set expandtab ts=4 sw=4 ai  " convert <TAB> key-presses to spaces
set smarttab            " Be smart when using tabs ;)

set shiftwidth=4        " number of spaces to use for each step of (auto)indent
set softtabstop=4       " backspace after pressing <TAB> will remove up to this many spaces

set autoindent          " copy indent from current line when starting a new line
set smartindent         " even better autoindent (e.g. add indent after '{')

"""" Search settings
set incsearch           " search as characters are entered
set hlsearch            " highlight matches

" Configure backspace so it acts as it should act
set backspace=eol,start,indent
set whichwrap+=<,>,h,l

" Ignore case when searching
set ignorecase

" When searching try to be smart about cases
set smartcase

" Move a line of text
nmap <C-j> mz:m+<cr>`z
nmap <C-k> mz:m-2<cr>`z
vmap <C-j> :m'>+<cr>`<my`>mzgv`yo`z
vmap <C-k> :m'<-2<cr>`>my`<mzgv`yo`z

" move vertically by visual line
nnoremap j gj
nnoremap k gk

if has("cscope")
        " Look for a 'cscope.out' file starting from the current directory,
        " going up to the root directory.
        let s:dirs = split(getcwd(), "/")
        while s:dirs != []
                let s:path = "/" . join(s:dirs, "/")
                if (filereadable(s:path . "/cscope.out"))
                        execute "cs add " . s:path . "/cscope.out " . s:path . " -v"
                        break
                endif
                let s:dirs = s:dirs[:-2]
        endwhile

        set csto=0  " Use cscope first, then ctags
        set cst     " Only search cscope
        set csverb  " Make cs verbose
    " To do the first type of search, hit 'CTRL-\' (]?), followed by one of the
    " cscope search types above (s,g,c,t,e,f,i,d).  The result of your cscope
    " search will be displayed in the current window.  You can use CTRL-T to
    " go back to where you were before the search.
    "
        nmap <C-\>s :cs find s <C-R>=expand("<cword>")<CR><CR>
        nmap <C-\>g :cs find g <C-R>=expand("<cword>")<CR><CR>
        nmap <C-\>c :cs find c <C-R>=expand("<cword>")<CR><CR>
        nmap <C-\>t :cs find t <C-R>=expand("<cword>")<CR><CR>
        nmap <C-\>e :cs find e <C-R>=expand("<cword>")<CR><CR>
        nmap <C-\>f :cs find f <C-R>=expand("<cfile>")<CR><CR>
        nmap <C-\>i :cs find i ^<C-R>=expand("<cfile>")<CR>$<CR>
        nmap <C-\>d :cs find d <C-R>=expand("<cword>")<CR><CR>
        nmap <F6> :cnext <CR>
        nmap <F5> :cprev <CR>

        " Open a quickfix window for the following queries.
        set cscopequickfix=s-,c-,d-,i-,t-,e-,g-
        noremap <F9> :copen 10<cr>
        noremap <F10> :cclose<cr>
endif
```

## Cheatsheet

1. Exit and save multiple opened vim panes
   ```bash
:wqa
```

2.  Exit without save
   ```bash
:q!
```

3.  Insert / append in beggining / end of line (similar to `i, a`)
   ```bash
I, A
```

4.  Open newline below / above
   ```bash
o, O
```

5.  Go to prior / next word, only spaces serves as separators (unlike `b, w`)
   ```bash
B, W
```

6.  Delete from current cursor location to end of line
   ```bash
D
```

7.  Undo, redo
   ```bash
u, ctrl + R
```

8.  Delete word, while being inside of it
```
diw
```
 
 9. Delete all stuff between opening bracket to closing bracket, works anywhere inside of it
```
di(
di{
di[
```

10.  Go to the pairing bracket
```
%
```
 
11. Go to file start, file end
```
gg, G
```
 
12.  Copy next 5 lines
```
5yy
```
 
13.  Delete word, while being inside of it
```
diw
```
 
14. Visual line mode, visual block mode (good for coloun oriented editing)
```bash
V
ctrl + V
```

15. Indentation
```bash
<visual-mode>
<, > shifts the block
= indents the block 

<outside-visual-mode>
<<, >> shifts current line
== indents line
```

16. Repeat last operation
```bash
.
```

17. Centerize current line
```bash
zz
```


18. Swap all occurances of `foo` to `bar`
```bash
:%s/foo/bar/g
```
