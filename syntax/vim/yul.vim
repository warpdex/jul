" Forked from https://github.com/mattdf/vim-yul/blob/master/syntax/yul.vim
" Originally written by Matthew Di Ferrante

if exists("b:current_syntax")
  finish
end

let b:current_syntax = "yul"

" Comment
syn keyword yulTodo          TODO FIXME XXX TBD contained
syn match   yulLineComment   "\/\/.*" contains=@Spell,yulTodo
syn region  yulMultiComment  start="/\*" end="\*/" contains=@Spell,yulTodo

" Constant
syn region  yulString        start=+"+ skip=+\\\\\|\\$"+ end=+"+
syn match   yulCharacter     /'\\\=.'/
syn match   yulNumber        /-\=\<\d\+\>/
syn match   yulHexNumber     /-\=0x[a-fA-F0-9]\+/
syn keyword yulBoolean       true false
syn keyword yulConstants     UINT8_MAX UINT16_MAX UINT24_MAX UINT32_MAX
\                            UINT40_MAX UINT48_MAX UINT56_MAX UINT64_MAX
\                            UINT96_MAX UINT128_MAX UINT160_MAX UINT192_MAX
\                            UINT224_MAX UINT256_MAX INT8_MIN INT8_MAX INT16_MIN
\                            INT16_MAX INT24_MIN INT24_MAX INT32_MIN INT32_MAX
\                            INT40_MIN INT40_MAX INT48_MIN INT48_MAX INT56_MIN
\                            INT56_MAX INT64_MIN INT64_MAX INT96_MIN INT96_MAX
\                            INT128_MIN INT128_MAX INT160_MIN INT160_MAX
\                            INT192_MIN INT192_MAX INT224_MIN INT224_MAX
\                            INT256_MIN INT256_MAX BLAKE2B_IV1 BLAKE2B_IV2

" Statement
syn keyword yulConditional   if elif else switch
syn keyword yulRepeat        for while do
syn keyword yulLabel         case default
syn match   yulAssign        /[:|]=\|)\s*\zs->/
syn keyword yulKeyword       object code let leave break continue const emit
\                            throw returns constructor interface pragma contract
syn match   yulKeyword       /\<data\>\ze "/
syn keyword yulFunction      function event error macro
syn match   yulFunction      /\<method\>\ze/

" Type
syn keyword yulType          uint int bytes bool string indexed
syn match   yulType          /\<address\>\ze/
syn match   yulType          /\<u\=int[0-9]\+\|bytes[0-9]\+\>/
syn match   yulType          /:\s*\zs[a-zA-Z_$][a-zA-Z_$0-9.]*/
syn keyword yulStorageClass  internal external private public
syn keyword yulStructure     struct enum

" Special
syn keyword yulAttribute     pure view payable anonymous packed
\                            optimize unchecked inline noinline
syn keyword yulOpcodes       stop add sub mul div sdiv mod smod exp not lt gt
\                            slt sgt eq iszero and or xor byte shl shr sar
\                            addmod mulmod signextend keccak256 pc pop mload
\                            mstore mstore8 sload sstore msize gas balance
\                            selfbalance caller callvalue calldataload
\                            calldatasize calldatacopy codesize codecopy
\                            extcodesize extcodecopy returndatasize
\                            returndatacopy extcodehash create create2 call
\                            callcode delegatecall staticcall return revert
\                            selfdestruct invalid log0 log1 log2 log3 log4
\                            chainid origin gasprice blockhash coinbase
\                            timestamp number difficulty gaslimit datacopy
\                            dataoffset datasize setimmutable loadimmutable
\                            linkersymbol memoryguard basefee prevrandao
\                            tload tstore
syn match   yulOpcodes       /\<address\>\ze()/
syn match   yulOpcodes       /\<verbatim_[0-9]\+i_[0-9]\+o\>/
syn keyword yulBuiltin       selector require neq lte gte slte sgte ucmp scmp neg
\                            testn maskn isset read8 read16 read24 read32 read40
\                            read48 read56 read64 read96 read128 read160 read192
\                            read224 write8 write16 write24 write32 write40
\                            write48 write56 write64 write96 write128 write160
\                            write192 write224 put8 put16 put24 put32 put40
\                            put48 put56 put64 put96 put128 put160 put192 put224
\                            mstoren mstore16 mstore24 mstore32 mstore40
\                            mstore48 mstore56 mstore64 mstore96 mstore128
\                            mstore160 mstore192 mstore224 mstore256 bswap16
\                            bswap32 bswap64 safeadd safesub safemul safeshl
\                            safeaddn safeadd8 safeadd16 safeadd24 safeadd32
\                            safeadd40 safeadd48 safeadd56 safeadd64 safeadd96
\                            safeadd128 safeadd160 safeadd192 safeadd224
\                            safeadd256 safeload calldata include storeimmutable
\                            construct sizeof bitsof ripemd160 sha256 hash160
\                            hash256 keccak160 blake2b160 blake2b256 mzero mcopy
\                            assert debug defined undefine andl orl notl submod
\                            negmod datareference tsel ecrecover ecverify
\                            blake2f safediv safesdiv safemod log10 log256
\                            bitlen declen octlen digits2 digits10 digits256
\                            umin umax smin smax abs sign popcount ctz clz
\                            mstores verbatim offsetof undefined safemuln
\                            safeshln
syn match   yulBuiltin       /\<method\.\(check\|call\|select\)\>/
syn match   yulBuiltin       /\<mutex\.\(init\|check\|lock\|unlock\)\>/
syn match   yulBuiltin       /\<eth\.\(send\|transfer\)\>/
" syn match   yulBuiltin       /\<require\.\(zero\|before\|after\|owner\)\>/
syn match   yulSpecial       /[@+]/

" Error
syn match   yulBadAssign     /\zs=\ze/
syn match   yulSemicolon     /;$/

" Comment
hi def link yulTodo          Todo
hi def link yulLineComment   Comment
hi def link yulMultiComment  Comment

" Constant
hi def link yulString        String
hi def link yulCharacter     Character
hi def link yulNumber        Number
hi def link yulHexNumber     Number
hi def link yulBoolean       Boolean
hi def link yulConstants     Constant

" Statement
hi def link yulConditional   Conditional
hi def link yulRepeat        Repeat
hi def link yulLabel         Label
hi def link yulAssign        Operator
hi def link yulKeyword       Keyword
hi def link yulFunction      Keyword

" Type
hi def link yulType          Type
hi def link yulStorageClass  StorageClass
hi def link yulStructure     Structure

" Special
hi def link yulAttribute     Special
hi def link yulOpcodes       Special
hi def link yulBuiltin       Special
hi def link yulSpecial       Special

" Error
hi def link yulBadAssign     Error
hi def link yulSemicolon     Error
