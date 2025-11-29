from .algo import *
import json

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
submodule1_path = os.path.join(parent_dir)
if submodule1_path not in sys.path:
    sys.path.append(submodule1_path)

from protocols import *

data = {
    'module':'',
    'version':'',
    'items' : []
}

class FuncCodePathAlgo(Algo):
    def __init__(self):
        pass

    @override
    def run(self,ctx: Context):
        logger.info('ida code path')
        data['module'] = 'ntoskrnl'
        data['version'] = '10.0.0'
        data['items'] = []
        with ida_domain.Database.open(ctx.file, ctx.idaoption, False) as db:
            gs = GraphStub("ntoskrnl")
            for func in db.functions:
                func_name = db.functions.get_name(func)
                uint = {'name': '','callers' :[],'callees' :[]}
                uint['name'] = func_name
                uint['callers'] = list(map(lambda x: db.functions.get_name(x),db.functions.get_callers(func)))
                uint['callees'] = list(map(lambda x: db.functions.get_name(x),db.functions.get_callees(func)))
                data['items'].append(uint)
                [gs.add_edge(x,func_name) for x in uint['callers']]
                [gs.add_edge(func_name,x) for x in uint['callees']]
            
            try:
                logger.info(gs.query_shortest_path('NtOpenProcess','PsGetProcessId'))
            except:
                pass
        with open("output.json", "w") as f:
            json.dump(data, f, indent=4)
    @override
    def get_results(self):
        '''Different result format with the different ida automation workflow alogrithm(IDAWA)
        '''
        pass