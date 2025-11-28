from .algo import *

class FuncCodePathAlgo(Algo):
    def __init__(self):
        pass

    @override
    def run(self,ctx: Context):
        logger.info('ida code path')
        pass

    @override
    def get_results(self):
        '''Different result format with the different ida automation workflow alogrithm(IDAWA)
        '''
        pass

def analyze_functions(
    db_path: str, pattern: str = 'main', max_results: int = 10, analyze_lvars: bool = True
) -> None:
    """Find and analyze functions matching a pattern."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=False)
    with ida_domain.Database.open(db_path, ida_options, False) as db:
        # Find functions matching a pattern
        matching_functions = []
        for func in db.functions:
            func_name = db.functions.get_name(func)
            if func_name != 'RtlpMuiRegCreateKernelRegistryInfo':
                continue
            logger.info(func_name)
            print('caller: ')
            print(list(map(lambda x: db.functions.get_name(x),db.functions.get_callers(func))))
            print('callee: ')
            print(list(map(lambda x: db.functions.get_name(x),db.functions.get_callees(func))))

            if  func_name.lower().startswith(pattern.lower()) or True:
                matching_functions.append((func, func_name))

        logger.debug(f"Found {len(matching_functions)} functions matching '{pattern}':")

        # Limit results if requested
        display_functions = (
            matching_functions[:max_results] if max_results > 0 else matching_functions
        )

        for func, name in display_functions:
            logger.debug(f'\nFunction: {name}')
            logger.debug(f'\nAddress: {hex(func.start_ea)} - {hex(func.end_ea)}')

            # Get signature
            signature = db.functions.get_signature(func)
            logger.debug(f'\nSignature: {signature}')

            # Get basic blocks
            flowchart = db.functions.get_flowchart(func)
            logger.debug(f'\nBasic blocks count: {len(flowchart)}')

        if max_results > 0 and len(matching_functions) > max_results:
            logger.debug(f'\n... (showing first {max_results} of {len(matching_functions)} matches)')
