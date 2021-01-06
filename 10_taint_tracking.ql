import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

// custom class that gets the location of calls to the mntohs,ntohl,ntohll macross
class NetworkByteSwap extends Expr {
    NetworkByteSwap () {
      exists(MacroInvocation mi | mi.getMacroName().regexpMatch("ntoh(s|l|ll)") 
      and this = mi.getExpr())
    } 
  }
class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }
  override predicate isSource(DataFlow::Node source) {
    // TODO check if the source of belongs to one of the macros
    source.asExpr() instanceof NetworkByteSwap
  }
  override predicate isSink(DataFlow::Node sink) {
    // TODO
    exists(FunctionCall fc | fc.getTarget().getName() = "memcpy"
      and sink.asExpr() = fc.getArgument(2))
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"