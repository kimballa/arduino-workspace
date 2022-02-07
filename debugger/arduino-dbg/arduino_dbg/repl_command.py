# (c) Copyright 2022 Aaron Kimball

"""
Decorators to define REPL commands, auto completion, etc.
Methods to tokenize command input, and print per-command help messages.
"""

import inspect
import os
import os.path
import readline
import shlex
from sortedcontainers import SortedDict, SortedList
import sys
import traceback

import arduino_dbg.term as term
from arduino_dbg.term import MsgLevel


class Completions(object):
    """
    Enumeration of valid autocomplete token classes.
    These can be used as entries in the `completions` list argument to @Command, and
    are interpreted by the ReplAutocompleter to query the right set of possibilities.
    """
    NONE = ''                   # A token that is uncompletable. Used as 'filler' in the
                                # completions list, before later completable token positions.
    KW = 'kw'                   # Another keyword that starts with the token as prefix.
    SYM = 'sym'                 # A symbol name that starts with the token as prefix.
    TYPE = 'type'               # A type name that starts with the token as prefix.
    SYM_OR_TYPE = 'sym/type'    # Either a symbol or a type name.
    WORD_SIZE = 'word_size'     # An integer that's a valid word size {1, 2, 4}.
    BINARY = 'binary'           # Values 0 and 1.
    BASE = 'base'               # integer base: 2, 8, 10, 16.
    CONF_KEY = 'conf_key'       # A configuration key.
    PATH = 'path'               # A file path.


class Command(object):
    """
    meta-decorator that tags a given function as a command that can be executed in the repl.
    Binds the keyword(s) to the function, registers the function's docstring as its help
    text, and the first non-empty line of the function's docstring as its short help text
    shown by the 'help' command.

    @param keywords is a list of keywords that trigger the command function.
    @return a decorator that directly returns its function argument unmodified.
    """

    _cmd_map = {}                 # Lookup from all keywords to Command instances
    _cmd_index = SortedDict()     # Set of Command instances keyed by primary keyword only.
    _cmd_list = SortedList()      # Sorted list of all keywords.
    _cmd_syntax_completions = {}  # Instructions indicating the kinds of tokens that can follow
                                  # each keyword, for use in tab autocompletion.

    def __init__(self, keywords, help_keywords=None, display_help=True, completions=None):
        self.keywords = keywords  # Set of keywords that activate this command.
        self.help_keywords = help_keywords or []  # Additional keywords to display in cmd summary.
        self.command_func = None  # The function to call (memoized in __call__)
        self.short_help = ''      # 1-line help summary extracted from fn docstring.
        self.long_help = ''       # Full help summary extracted from fn docstring.
        self.display_help = display_help  # Does this show up in the command summary?

        if not isinstance(keywords, list):
            raise Exception("Expected syntax @Command(keywords=[...])")

        if keywords is None or len(keywords) == 0:
            raise Exception("Must supply one or more keywords to @command.")

        # Register binding from each keyword to this object.
        for kw in keywords:
            if kw in Command._cmd_map:
                raise Exception(f"Warning: keyword '{kw}' used multiple times")
            Command._cmd_map[kw] = self
            Command._cmd_list.add(kw)
            Command._cmd_syntax_completions[kw] = completions

        # Register this in the full command map
        Command._cmd_index[keywords[0]] = self

    def invoke(self, repl, args):
        """
        Actually invoke the command function we decorated.

        @param repl the repl instance that owns the method.
        @param args the arg array to pass to the method.
        """

        return self.command_func(repl, args)  # repl is 'self' from pov of called method.

    def __call__(self, *args, **kwargs):
        """
        Memoize the actual function associated with this command, and extract help text
        from docstring.

            @Command(keywords=['x','y'])
            def some_fn(): ...

            is equivalent to:

            def some_fn(): ...
            some_fn = Command(keywords=['x','y'])(some_fn)

            ... is equivalent to...

            def some_fn(): ...
            c = Command(keywords=...)
            some_fn = c.__call__(some_fn)

        This callable method will be invoked with the function itself as the arg, to transform
        that function. We want to save the function argument as 'what we really invoke' and
        return the identity transformation in-place.

        """

        fn = args[0]
        self.command_func = fn  # The function argument is what we'll call to run the command.

        # The long help (shown in `help <kwd>`) is the entire cleanly-reformatted docstring,
        # along with the list of keyword synonyms to invoke it.
        all_keywords = []
        all_keywords.extend(self.keywords)
        all_keywords.extend(self.help_keywords)  # Some keywords like 'tm' show up as synonyms
                                                 # for <X> without activating <X> directly.

        if len(all_keywords) > 1:
            keywordsIntro = f"{all_keywords[0]} ({', '.join(all_keywords[1:])})"
        else:
            keywordsIntro = f"{all_keywords[0]}"

        # Get the docstring and eliminate method-level indentation.
        if fn.__doc__ is not None:
            docstring = inspect.cleandoc(fn.__doc__)
        else:
            docstring = ""
        # Split into lines; if one line matches `Syntax: <foo>`, make that line bold.
        docstr_lines = docstring.split("\n")
        for i in range(0, len(docstr_lines)):
            if docstr_lines[i].strip().startswith("Syntax:"):
                # Replace this line with *bold*
                docstr_lines[i] = term.fmt(docstr_lines[i], term.BOLD)
                break  # Only need to bold one syntax line.
        docstring = "\n".join(docstr_lines)

        helptext = f"    {keywordsIntro}\n\n{docstring}"
        self.long_help = helptext

        # The short help (shown in the `help` summary) is the keyword list and
        # the first non-empty line of the docstring.
        if len(docstr_lines) == 1:
            self.short_help = f'{keywordsIntro} -- {docstring.strip()}'
        else:
            first_real_line = None
            for line in docstr_lines:
                if len(line.strip()) > 0:
                    first_real_line = line.strip()
                    break
            if first_real_line:
                self.short_help = f'{keywordsIntro} -- {first_real_line}'
            else:
                # Just use.. the entire (empty?) docstring
                self.short_help = f'{keywordsIntro} -- {docstring.strip()}'

        return fn

    @classmethod
    def getCommandMap(cls):
        """
        Return full mapping from keywords to Command instances.
        """
        return cls._cmd_map

    @classmethod
    def getCommandIndex(cls):
        """
        Return sorted mapping from primary keyword to Command instances.
        """
        return cls._cmd_index

    @classmethod
    def getCommandList(cls):
        """
        Return sorted list of keywords.
        """
        return cls._cmd_list

    @classmethod
    def getCommandCompletions(cls, keyword):
        """
        Return a list of completion tokens accepted by each keyword
        """
        try:
            return cls._cmd_syntax_completions[keyword]
        except KeyError:
            return None


def CompoundHost(cls):
    """
    Decorator that annotates a class that contains @CompoundCommand-decorated methods.
    Used to pull the class name into the namespace of the repl_command module, so we can
    do lazy-instantiation of instances of this class to use for 'self' in CompoundCommand.invoke().
    """
    globals()[cls.__name__] = cls  # Pull this class into our namespace.
    return cls  # return class unmodified.


class CompoundCommand(object):
    """
    meta-decorator that tags a given function as a two word command that can be executed in the
    repl. Binds a keyword pair (`breakpoint list`) to a function, registers its docstring as its
    help text, and the first non-empty line of the function's docstring as its short help text
    shown by the 'help' command.

    Methods decorated with @CompoundCommand must be inside a class decorated as @CompoundHost.
    """

    _cmd_map = {}                 # Lookup from all (kw1, kw2) pairs to CompoundCommand instances

    _compound_leaders = set()     # Set of all valid 'kw1' semi-keywords.

    def __init__(self, kw1, kw2, cls):
        if not isinstance(kw1, list) or not isinstance(kw2, list):
            raise Exception("Expected syntax @CompoundCommand(kw1=[...], kw2=[...])")

        self.kw1 = kw1  # The list of initial keywords (foo1, foo2)
        self.kw2 = kw2  # The list of secondary keywords (bar1, bar2)
                        # ... this can be executed as `foo1 bar1`, `foo1 bar2`, `foo2 bar1` ...

        self.cls = cls  # Name of the class that owns this method. Passed as a strong to avoid
                        # self-reference issues during class definitions. An instance of this
                        # class will be created w/ repl as c'tor arg by make_self() at command
                        # invocation time.

        self.command_func = None  # The function to call (memoized in __call))
        self.short_help = ''      # 1 line help summary from docstring
        self.long_help = ''       # Full help summary from docstring.
        self.display_help = True  # Does this show up in the command summary?

        for primary in kw1:
            for secondary in kw2:
                if (primary, secondary) in CompoundCommand._cmd_map:
                    raise Exception(f"Warning: keyword '{primary} {secondary}' used multiple times")
                CompoundCommand._cmd_map[(primary, secondary)] = self

                # Add leading keyword to autocomplete list for token 0.
                if primary not in Command._cmd_list:
                    Command._cmd_list.add(primary)

            # Register 'primary' as a semi-command (a keyword that needs a 2nd keyword)
            CompoundCommand._compound_leaders.add(primary)

            # Add secondary keywords to autocomplete list for token 0.
            if primary not in Command._cmd_syntax_completions:
                Command._cmd_syntax_completions[primary] = [[]]

            Command._cmd_syntax_completions[primary][0].extend(kw2)

        # Register in full command index for help.
        Command._cmd_index[f'{kw1[0]} {kw2[0]}'] = self

    def make_self(self, repl):
        # 'self.cls' contains the name of the class (as a string) that owns the function to invoke.
        # Create an instance of it to use as 'self' when invoking the method.
        class_proto = getattr(sys.modules[__name__], self.cls)
        return class_proto(repl)

    def invoke(self, repl, args):
        """
        Actually invoke the command function we decorated.

        @param repl the active repl instance
        @param args the arg array to pass to the method.
        """

        return self.command_func(self.make_self(repl), args)  # repl passed to c'tor for 'self' object

    def __call__(self, *args, **kwargs):
        """
        Memoize the actual function associated with this command, and extract help text
        from docstring.

            @CompoundCommand(kw1=['a1', 'a2'], kw2=['b1', 'b2'], cls=Foo)
            def some_fn(): ...

        Enables REPL to invoke Foo(repl).some_fn(args...) via 'a1 b1 args..', 'a1 b2 args..', ...

        This callable method will be invoked with the function itself as the arg, to transform
        that function. We want to save the function argument as 'what we really invoke' and
        return the identity transformation in-place.
        """

        fn = args[0]
        self.command_func = fn  # The function argument is what we'll call to run the command.

        # The long help (shown in `help <kwd>`) is the entire cleanly-reformatted docstring,
        # along with the list of keyword synonyms to invoke it.
        if len(self.kw1) > 1:
            firstKeywordsIntro = f"{self.kw1[0]} ({', '.join(self.kw1[1:])})"
        else:
            firstKeywordsIntro = f"{self.kw1[0]}"

        if len(self.kw2) > 1:
            secondKeywordsIntro = f"{self.kw2[0]} ({', '.join(self.kw2[1:])})"
        else:
            secondKeywordsIntro = f"{self.kw2[0]}"

        keywordsIntro = firstKeywordsIntro + ' ' + secondKeywordsIntro

        # Get the docstring and eliminate method-level indentation.
        docstring = inspect.cleandoc(fn.__doc__)
        # Split into lines; if one line matches `Syntax: <foo>`, make that line bold.
        docstr_lines = docstring.split("\n")
        for i in range(0, len(docstr_lines)):
            if docstr_lines[i].strip().startswith("Syntax:"):
                # Replace this line with *bold*
                docstr_lines[i] = term.fmt(docstr_lines[i], term.BOLD)
                break  # Only need to bold one syntax line.
        docstring = "\n".join(docstr_lines)

        helptext = f"    {keywordsIntro}\n\n{docstring}"
        self.long_help = helptext

        # The short help (shown in the `help` summary) is the keyword list and
        # the first non-empty line of the docstring.
        if len(docstr_lines) == 1:
            self.short_help = f'{keywordsIntro} -- {docstring.strip()}'
        else:
            first_real_line = None
            for line in docstr_lines:
                if len(line.strip()) > 0:
                    first_real_line = line.strip()
                    break
            if first_real_line:
                self.short_help = f'{keywordsIntro} -- {first_real_line}'
            else:
                # Just use.. the entire (empty?) docstring
                self.short_help = f'{keywordsIntro} -- {docstring.strip()}'

        return fn

    @classmethod
    def getCommandMap(cls):
        """
        Return full mapping from keywords to CompoundCommand instances.
        """
        return cls._cmd_map

    @classmethod
    def is_compound_leader(cls, leader):
        """
        Return True if 'leader' is the first keyword in a compound command.
        """
        return leader in cls._compound_leaders


class ReplAutoComplete(object):
    """
    readline autocompleter for debugger repl.
    """

    def __init__(self, debugger):
        self._debugger = debugger
        self._cached_key = None     # (prefix, tokens, state) of previous request.
        self._cached_result = None  # Last cached completion-suggestions value.

    def clear_cache(self):
        self._cached_key = None
        self._cached_result = None

    @staticmethod
    def __filter(iterable, prefix):
        """
        Helper method: return only elements of the list that start with the prefix.
        """
        return list(filter(lambda item: item.startswith(prefix), iterable))

    def _complete_keyword(self, prefix):
        """
        Return completions for keyword
        """
        if prefix is None or len(prefix) == 0:
            nextfix = None
        else:
            last_char = prefix[-1]
            next_char = chr(ord(last_char) + 1)
            nextfix = prefix[0:-1] + next_char

        return Command.getCommandList().irange(prefix, nextfix, inclusive=(True, False))

    def _complete_symbol(self, prefix):
        return self._debugger.syms_by_prefix(prefix)

    def _complete_type(self, prefix):
        lst = SortedList()
        # ParsedDebugInfo.types() iteratively yields tuples of (typename, typedata). Just keep the name.
        lst.update([elt[0] for elt in self._debugger.get_debug_info().types(prefix)])
        return lst

    def _complete_symbol_or_type(self, prefix):
        lst = SortedList()
        lst.update(self._complete_symbol(prefix))
        lst.update(self._complete_type(prefix))
        return lst

    def _complete_conf_key(self, prefix):
        conf_keys = self._debugger.get_conf_keys()
        return self.__filter(conf_keys, prefix)

    def _complete_path(self, prefix):
        # See e.g. http://schdbr.de/python-readline-path-completion/
        if prefix is None or len(prefix) == 0:
            searchdir = '.'
            result_prepend = ''
            file_prefix = ''
        elif prefix.endswith(os.path.sep):
            # Prefix as-is is the directory to list.
            searchdir = prefix
            result_prepend = ''
            file_prefix = ''
        else:
            # Iterate over parent dir of the complete prefix
            searchdir = os.path.dirname(prefix)
            result_prepend = searchdir
            if searchdir is None or len(searchdir) == 0:
                searchdir = '.'
            file_prefix = os.path.basename(prefix)

        # Iterate through everything in the search dir.
        if not os.path.isabs(searchdir):
            searchdir = os.path.abspath(searchdir)

        contents = os.listdir(searchdir)
        # But only keep the ones that start with the prefix.
        contents = list(filter(lambda item: item.startswith(file_prefix), contents))
        contents = [os.path.join(result_prepend, elem) for elem in contents]
        # Append '/' to directory elements.
        for i in range(0, len(contents)):
            if os.path.isdir(contents[i]):
                # Completing to a directory should make next [tab] show items within that directory.
                contents[i] = contents[i] + os.path.sep
            else:
                # files are complete items and should advance to next token
                contents[i] = contents[i] + ' '

        return contents

    def _space(self, suggestions):
        """
        Add a space after each suggestion to advance to the next token in the autocomplete sequence.
        """
        return [item + ' ' for item in suggestions]

    def _suggest(self, tokens, prefix):
        if len(tokens) == 0 or len(tokens) == 1:
            # We are trying to suggest the first token in the line, which is always a keyword.
            return self._space(self._complete_keyword(prefix.strip()))

        # Otherwise, we need to recommend a keyword-specific next token.
        keyword = tokens[0].strip()
        arg_tokens = tokens[1:]
        # Get a list of the form [ clsA, clsB, clsC ] where clsA..C are strings in the
        # 'Completions' string enumeration. Each of these defines the set of things that
        # can be completed in each successive position of the arguments to the keyword.
        completion_sets = Command.getCommandCompletions(keyword)
        if completion_sets is None or len(completion_sets) < len(arg_tokens):
            # We can't complete this far into the token set for this command
            return []

        # Get the completion set relevant to the current token
        completion_set = completion_sets[len(arg_tokens) - 1]
        if completion_set == Completions.NONE:
            return []  # No suggestions
        elif completion_set == Completions.KW:
            return self._space(self._complete_keyword(prefix))
        elif completion_set == Completions.SYM:
            return self._space(self._complete_symbol(prefix))
        elif completion_set == Completions.TYPE:
            return self._space(self._complete_type(prefix))
        elif completion_set == Completions.SYM_OR_TYPE:
            return self._space(self._complete_symbol_or_type(prefix))
        elif completion_set == Completions.WORD_SIZE:
            return self._space(self.__filter(['1', '2', '4'], prefix))
        elif completion_set == Completions.BINARY:
            return self._space(self.__filter(['0', '1'], prefix))
        elif completion_set == Completions.BASE:
            return self._space(self.__filter(['2', '8', '10', '16'], prefix))
        elif completion_set == Completions.CONF_KEY:
            return self._space(self._complete_conf_key(prefix))
        elif completion_set == Completions.PATH:
            return self._complete_path(prefix)
        elif isinstance(completion_set, list):
            # Completion set is itself a set of explicit choices.
            return self._space(list(filter(lambda choice: choice.startswith(prefix), completion_set)))

        # Don't know what this completion set is supposed to be.
        raise Exception(f"Unknown completion set: '{completion_set}'")


    def complete(self, prefix, state):
        """
        Main interface method for readline autocomplete.
        We are passed the current token to complete as 'text' and the iteration number in 'state'.
        Incrementally higher 'state' values should yield subsequently-indexed suggestions.
        """
        try:
            line_buffer = readline.get_line_buffer()
            try:
                tokens = repl_split(line_buffer, incomplete_ok=True)
            except ValueError:
                # Even with quote-fixing, couldn't actually figure out what to do.
                # Don't suggest anything.
                return None

            if not tokens or line_buffer[-1] == ' ':
                tokens.append('')

            # If this is the next 'state' for the same search, short-circuit by
            # returning the next value in the cached suggestion result list.
            expected_cache_key = (prefix, line_buffer, state - 1)
            if self._cached_key == expected_cache_key and self._cached_result is not None:
                # Cache hit
                self._cached_key = (prefix, line_buffer, state)
                return self._cached_result[state]

            results = list(self._suggest(tokens, prefix))
            results.append(None)  # Append a 'None' to the end to signal
                                  # stop-iteration condition to readline.

            # Cache the result on the way out, along with a key to ensure we're still on the same
            # search next time we try to access a cached result.
            self._cached_key = (prefix, line_buffer, state)
            self._cached_result = results

            return results[state]  # state is an index into the output list.

        except Exception as e:
            # readline swallows our exceptions. Print them out, because we need to know
            # what's going on.
            print(f'\nException in autocomplete: {e}')
            if self._debugger.get_conf("dbg.verbose"):
                traceback.print_tb(e.__traceback__)
            raise  # rethrow


def repl_split(cmdline, incomplete_ok=False):
    """
    Split a repl commandline into tokens. We allow 'single quotes' or "double quotes" to preserve
    whitespace within a token. There is no escape character; shortcuts like '\\q' are returned
    as-is. Unlike shlex in its posix=False settinsg, we strip '"containing quotes"' from token
    responses.

    @param cmdline the line to tokenize
    @param incomplete_ok - if True, don't freak out at unclosed quote marks; attempt to
        complete the quotes and try again. If False, unclosed quotes raise ValueError.
    @return a list of whitespace-separated tokens from cmdline.
    """
    try:
        return shlex.split(cmdline, posix=False)
    except ValueError:
        if not incomplete_ok:
            # Got incomplete quotation marks.
            raise  # re-throw
        else:
            single_q = None
            double_q = None
            try:
                single_q = cmdline.rindex("'")
            except ValueError:
                # no single quote at all. That's fine.
                pass

            try:
                double_q = cmdline.rindex('"')
            except ValueError:
                # no double quote at all. That's fine.
                pass

            if double_q is None and single_q is None:
                raise  # No idea how to process a ValueError w/o any open-quote issues.
            elif double_q is None and single_q is not None:
                # Try again with closed single-quote.
                return repl_split(cmdline.rstrip() + "'", False)
            elif double_q is not None and single_q is None:
                # Try again with closed double-quote.
                return repl_split(cmdline.rstrip() + '"', False)
            elif double_q > single_q:
                # A double-quote was likely left hanging open.
                return repl_split(cmdline.rstrip() + '"', False)
            else:
                # A single-quote was likely left hanging open.
                return repl_split(cmdline.rstrip() + "'", False)


def print_help_for_leading_keyword(debugger, cmd):
    """
    If we were asked for 'help foo' when there is a set of 'foo bar', 'foo baz', etc. commands,
    print the set of commands with compound keywords that start with 'foo'.

    @param cmd the "leader keyword" for this set of compound-keyword commands.
    """
    # Note that 'cmd' might be an alias for the canonical commands (e.g. 'bp' instead of
    # 'breakpoint). In which case we won't see subcommands available in the command
    # index. Start by getting the *canonical* keyword for the command: the first one in the kw1
    # list of each @CompoundCommand decoration.

    # Start with the map of all compound commands.
    compound_cmd_map = CompoundCommand.getCommandMap()
    # Find one or more with a leader keyword that matches 'cmd'.
    compatible_compounds = list(filter(lambda kw1_kw2: kw1_kw2[0] == cmd, compound_cmd_map))
    assert len(compatible_compounds) > 0  # (Otherwise cmd shouldn't be is_compound_leader())
    # Get the first such compound keyword command as a 'reference' command.
    leader_cmd_ref = compound_cmd_map[compatible_compounds[0]]
    # ... and get its *first* alias in its first-keyword list. This is the canonical
    # leader keyword for this set of compound-keyword commands.
    canonical_leader = leader_cmd_ref.kw1[0]

    # Now search the main command index for compound keywords that begin with that
    # canonical leader keyword.
    cmd_index = Command.getCommandIndex()
    compound_cmds = list(filter(lambda full_cmd: full_cmd.startswith(canonical_leader + ' '),
                                cmd_index))
    debugger.msg_q(MsgLevel.INFO, f"'{canonical_leader}' Commands")
    debugger.msg_q(MsgLevel.INFO, (len(canonical_leader) + 11) * "-")
    for full_cmd in compound_cmds:
        cmd_obj = cmd_index[full_cmd]
        if cmd_obj.display_help:
            debugger.msg_q(MsgLevel.INFO, cmd_obj.short_help)

    debugger.msg_q(MsgLevel.INFO, f"\nType 'help {cmd} <subcommand>' for more details.")


def print_command_help(debugger, argv):
    """
    Print help on available commands.

    @param debugger the debugger with a print queue.
    @param argv a list of strings from the REPL. Usually argv[0] is the keyword to look up.
        For compound commands, this may be in (argv[0], argv[1]). If an empty list, prints
        a list of available commands.
    """
    if argv is None:
        argv = []

    if len(argv) > 1 and CompoundCommand.is_compound_leader(argv[0]):
        # Multi-keyword compound command detected based on first keyword.
        try:
            primary = argv[0]
            secondary = argv[1]
            cmdMap = CompoundCommand.getCommandMap()
            cmdObj = cmdMap[(primary, secondary)]
            debugger.msg_q(MsgLevel.INFO, cmdObj.long_help)
        except Exception:
            debugger.msg_q(MsgLevel.ERR, f"Error: No command '{argv[0]} {argv[1]}' found.")
            debugger.msg_q(MsgLevel.INFO, "Try 'help' to list all available commands.")
            debugger.msg_q(MsgLevel.INFO, "Use 'quit' to exit the debugger.")

        return
    elif len(argv) > 0:
        # Get help on single-keyword command.
        try:
            cmd = argv[0]
            cmd_map = Command.getCommandMap()
            cmd_obj = cmd_map[cmd]
            debugger.msg_q(MsgLevel.INFO, cmd_obj.long_help)
        except Exception:
            if CompoundCommand.is_compound_leader(cmd):
                # List compound commands that start with this initial keyword.
                print_help_for_leading_keyword(debugger, cmd)
            else:
                debugger.msg_q(MsgLevel.ERR, f"Error: No command '{argv[0]}' found.")
                debugger.msg_q(MsgLevel.INFO, "Try 'help' to list all available commands.")
                debugger.msg_q(MsgLevel.INFO, "Use 'quit' to exit the debugger.")

        return

    # No command keyword specified -- just list all available commands.

    debugger.msg_q(MsgLevel.INFO, "Commands")
    debugger.msg_q(MsgLevel.INFO, "--------")

    cmd_index = Command.getCommandIndex()
    for (keyword, cmd_obj) in cmd_index.items():  # iterate over sorted map.
        if cmd_obj.display_help:
            debugger.msg_q(MsgLevel.INFO, cmd_obj.short_help)

    debugger.msg_q(MsgLevel.INFO, "")
    debugger.msg_q(
        MsgLevel.INFO,
        "After doing a symbol search with sym or '?', you can reference results by")
    debugger.msg_q(
        MsgLevel.INFO,
        "number, e.g.: `print #3`  // look up value of 3rd symbol in the list")
    debugger.msg_q(
        MsgLevel.INFO,
        "The most recently-used such number--or '#0' if '?' gave a unique result--can")
    debugger.msg_q(
        MsgLevel.INFO,
        "then be referenced as '$'. e.g.: `print $`  // look up the same value again")
    debugger.msg_q(MsgLevel.INFO, "")
    debugger.msg_q(MsgLevel.INFO, "For more information, type: help <command>")

