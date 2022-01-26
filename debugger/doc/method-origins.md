How should MethodInfo objects define ancestry/origin?
=====================================================

How do `DW_AT_specification` and `DW_AT_abstract_origin` interact for `DW_TAG_subprogram`
entries? Do each of these `DW_TAG_subprogram` entries define unique data that a third
`subprogram` of the same symbol needs to inherit? Or is one/either "parent" sufficient?)

Example:
--------

In the case of e.g. `NewhavenLcd0440::write()`, we have an initial method declaration
(#1), then another subprogram (#2) references it with `DW_AT_specification`. A third
subprogram of the same name references #2 with `DW_AT_abstract_origin`. Both #2 and #3 set
#1 as origin (when trying to find the origin for a `MethodInfo`, if we identify another
`MethodInfo` that itself has an origin, we recursively traverse and use the "top-most" in
this lineage); effectively this makes #2 and 3 "sibling" definitions in this pointer tree.
Should 3 point to 2 points to 1?

If we are doing a `locals` within #3, and #3 copied in or referred to all the variables
defined in #2, we may have more thorough enumeration of all local variables (some are
present in #2 and not #3) but they may have location eval instructions not valid for the
`$PC`...

