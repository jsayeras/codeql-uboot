
import cpp

from FunctionCall call
where
  call.getTarget().getName() = "memcpy"
select call, call.getTarget().getName(), "memcpy found!"