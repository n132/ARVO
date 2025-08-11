from unidiff import PatchSet
from tree_sitter import Language, Parser
from tree_sitter_cpp import language as CppLanguage
CPP_LANGUAGE = Language(CppLanguage())
parser = Parser(CPP_LANGUAGE)
from arvo import *

def get_changed_files(diff_path):
    with open(diff_path, 'r',encoding='utf-8',errors='ignore') as f:
        patch = PatchSet(f)
    return [patched_file.path for patched_file in patch]
        
def locateMdifiedFunctions(original_ctx, new_ctx,modified_func_only=True):
    fndefs_query = CPP_LANGUAGE.query("(function_definition) @function.def")
    def get_functions(src: bytes):
        tree = parser.parse(src)
        pre_parse = fndefs_query.captures(tree.root_node)
        if 'function.def' not in pre_parse:
            WARN("No function def")
            return []
        def_captures = pre_parse['function.def']
        defs = []
        for d in def_captures:
            ident_query = CPP_LANGUAGE.query("""
(
    function_declarator
    declarator: [(identifier) (qualified_identifier)] @function.name
    parameters: (parameter_list) @function.params
)
""")
            got  = ident_query.captures(d)
            if 'function.name' not in got or \
               'function.params' not in got:
                continue
            # 
            func_name = got['function.name']
            params = got['function.params']
            if len(func_name) == 0 : continue
            name_node = func_name[0]
            args_name = ''
            for param in params:
                args_name += param.text.decode(errors='ignore')
                
            defs += [(name_node.text.decode(errors='ignore'),d.text,args_name)]
        return defs

    changed_functions = []
    for x in original_ctx: # files
        print(x)
        orig_src = original_ctx[x]
        new_src = new_ctx[x]
        orig_funcs = {f"{name}-{params}": body for name, body, params in get_functions(orig_src)}
        new_funcs  = {f"{name}-{params}": body for name, body, params in get_functions(new_src)}
        if not modified_func_only:
            # Count the added functions 
            for name in new_funcs:
                if (name not in orig_funcs) or (orig_funcs[name] != new_funcs[name]):
                    changed_functions.append(name.split("-")[0])
        else:
            # Count the removed functions 

            for name in orig_funcs:
                if (name not in new_funcs) or (orig_funcs[name] != new_funcs[name]):
                    changed_functions.append(name.split("-")[0])

    return changed_functions
def getModifiedFunctions(localId):
    fix_commit = getFixCommit(localId)
    if not fix_commit:
        WARN("getModifiedFunctions: not fix commit found") 
        return False
    pname = getPname(localId)
    if not pname: 
        WARN("getModifiedFunctions: failed to getPname") 
        return False
    if1, if2 = get_projectInfo(localId,pname)
    if if1['url']!= if2['url'] or if1['type']!=if2['type'] or if1['type']!='git':
        WARN("getModifiedFunctions: info is confusing") 
        return False
    gt = GitTool(if1['url'],if1['type'])
    if not gt: 
        WARN("getModifiedFunctions: failed to get gt") 
        return False
    target_commit = gt.prevCommit(fix_commit[0]) if isinstance(fix_commit,list) else gt.prevCommit(fix_commit)
    if not target_commit:
        WARN("getModifiedFunctions: failed to get previous commit") 
        return False
    gt.reset(target_commit)
    diff_file = getDiff(localId)
    print(diff_file)
    files = get_changed_files(diff_file)
    original_ctx = {}
    for x in files:
        original_ctx[x] = open(gt.repo / x, 'rb').read() if (gt.repo / x).exists() else b''
    if not gt.patch(diff_file):
        WARN("getModifiedFunctions: failed to patch") 
        return False
    new_ctx = {}
    for x in files:
        new_ctx[x] = open(gt.repo / x, 'rb').read() if (gt.repo / x).exists() else b''
    res = locateMdifiedFunctions(original_ctx, new_ctx)
    return res
def TEST():
    issues = {
        42524804: ('main','Redis::info','Redis::lindex','Redis::lrange','HostPools::reloadPools','IEC104Stats::processPacket','LuaEngine::handle_script_request','ntop_clickhouse_exec_csv_query','NetworkInterface::dissectPacket','CustomFlowLuaScript::initVM','CustomHostLuaScript::initVM'),
        42538533:  ('Cr2Decompressor::decodeN_X_Y',),
        42502115: ('mrb_last_insn',),
        42524577: ('_bfd_stab_section_find_nearest_line',),
        42471184: set([]),
        42496045: ('NewCodePage','TouchSlot','CompileElseBlock','CompileBlock',),
        # 42536498: ('VRTRawRasterBand::SetRawLink',),
        42475674: ('archive_read_format_rar_read_data',),
        42541718: ('ps_underflow','ps_index'),
        42490980: ('cf2_font_setup','cf2_free_instance','cff_subfont_load','cff_font_done','cff_subfont_done','cff_font_load','cff_load_private_dict' ,'cf2_interpT2CharString','cff_face_done','cff_parse_num','cff_parser_run','TT_Get_MM_Var','TT_Set_MM_Blend')
    }
    for x in issues:
        got = getModifiedFunctions(x)
        print(got)
        if set(issues[x]) == set(got):
            SUCCESS(f"[PASS] CASE: {x}" )
        else:
            WARN(f"[FAIL] CASE: {x}" )
            WARN(f"{set(got)}")
            INFO(f"{set(issues[x])}")
if __name__ == "__main__":
    # todo = getReports()
    test_set = [42527008,42527435,42527636,42528141,42528604,42528877,42528997,42529484,42529804,42530091,42530206,42530453,42530568,42530920,42531117,42531314,42531940,42532863,42533922,42534845,42534902,42535152,42535569,42536079,42536536,42538086,42527012,42527438,42527736,42528175,42528680,42528883,42529030,42529507,42529812,42530097,42530230,42530520,42530604,42530947,42531126,42531481,42532259,42532885,42533950,42534851,42534913,42535166,42535635,42536107,42536593,42527015,42527467,42527741,42528228,42528694,42528891,42529037,42529524,42529909,42530105,42530284,42530523,42530618,42530963,42531141,42531506,42532339,42532942,42534044,42534862,42535235,42535808,42536108,42536641,42527328,42527509,42527895,42528235,42528698,42528894,42529061,42529542,42529915,42530108,42530341,42530547,42530675,42531033,42531143,42531532,42532360,42533480,42534512,42534870,42534941,42535258,42535828,42536112,42536963,42527383,42527526,42527948,42528352,42528740,42528938,42529112,42529650,42529931,42530135,42530439,42530548,42530705,42531092,42531145,42531542,42532498,42533504,42534536,42534875,42534950,42535348,42535840,42536161,42537128,42527401,42527540,42528035,42528416,42528757,42528949,42529327,42529661,42529975,42530151,42530446,42530550,42530723,42531108,42531203,42531547,42532684,42533540,42534645,42534876,42534959,42535447,42535969,42536250,42537225,42527409,42527545,42528049,42528426,42528792,42528951,42529360,42529681,42530069,42530168,42530447,42530554,42530823,42531113,42531212,42531613,42532747,42533629,42534760,42534891,42535056,42535461,42536001,42536271,42537493,42527431,42527550,42528067,42528530,42528850,42528972,42529482,42529687,42530090,42530195,42530451,42530559,42530909,42531115,42531269,42531837,42532756,42533913,42534812,42534894,42535147,42535524,42536064,42536363,42537987]
    xExplore(test_set,"Patched_Funcs.log",getModifiedFunctions)
    # res = getModifiedFunctions(42528604)
    # print(res)
    # TEST()