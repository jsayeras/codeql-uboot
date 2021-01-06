
import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    // TODO: replace <class> and <var>
    exists(MacroInvocation mi | mi.getMacroName().regexpMatch("ntohs|ntohl|ntohll")
    and this = mi.getExpr())

      // TODO: <condition>
  }
}

from NetworkByteSwap n
select n, "Network byte swap!!"