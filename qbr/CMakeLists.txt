build_lib(
  LIBNAME qbr
  SOURCE_FILES
    helper/qbr-helper.cc
    model/qbr-header.cc
    model/qbr-routing-table.cc
    model/qbr-q-table.cc
    model/qbr-message-handler.cc
    model/qbr-tuple-manager.cc
    model/qbr-routing-protocol.cc
    model/qbr-state.cc
    model/qbr-metric-engine.cc
  HEADER_FILES
    helper/qbr-helper.h
    model/qbr-header.h
    model/qbr-repositories.h
    model/qbr-routing-table.h
    model/qbr-q-table.h
    model/qbr-message-handler.h
    model/qbr-tuple-manager.h
    model/qbr-routing-protocol.h
    model/qbr-state.h
    model/qbr-types.h
    model/qbr-metric-engine.h
  LIBRARIES_TO_LINK ${libinternet}
)
