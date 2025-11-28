from .algo import *

class FuncLocalVariableAlgo(Algo):
    def __init__(self):
        pass

    @override
    def run(self,ctx: Context):
        pass

    @override
    def get_results(self):
        '''Different result format with the different ida automation workflow alogrithm(IDAWA)
        '''
        pass


def analyze_local_variables(db: Database, func: 'func_t') -> None:
    """Analyze local variables in a function."""
    try:
        lvars = db.functions.get_local_variables(func)
        if not lvars:
            logger.debug('  No local variables found')
            return

        logger.debug(f'  Local variables ({len(lvars)} total):')
        func_name = db.functions.get_name(func)
        for lvar in lvars:
            refs = db.functions.get_local_variable_references(func, lvar)
            ref_count = len(refs)
            var_type = 'arg' if lvar.is_argument else 'ret' if lvar.is_result else 'var'
            type_str = lvar.type_str if lvar.type else 'unknown'

            logger.debug(f'    {lvar.name} ({var_type}, {type_str}): {ref_count} refs')
            #logger.info(f'    {lvar.name} ({var_type}, {type_str}): {ref_count} refs')
            if '[' in type_str or ']' in type_str or 'int16' in {type_str}:
                print(f'[fruits]  {func_name}  {lvar.name} ({var_type}, {type_str}): {ref_count} refs')

            # Show first reference with line info if available
            if refs and refs[0].line_number is not None:
                first_ref = refs[0]
                logger.debug(f'      first ref at line {first_ref.line_number}: {first_ref.code_line}')
    except RuntimeError as e:
        pass
