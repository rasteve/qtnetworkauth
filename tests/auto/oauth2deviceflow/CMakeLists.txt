# Copyright (C) 2024 The Qt Company Ltd.
# SPDX-License-Identifier: BSD-3-Clause

list(APPEND test_data "../shared/certs")

qt_internal_add_test(tst_oauth2deviceflow
    SOURCES
        ../shared/webserver.h
        ../shared/tlswebserver.h
        tst_oauth2deviceflow.cpp
    INCLUDE_DIRECTORIES
        ../shared
    LIBRARIES
        Qt::CorePrivate
        Qt::Network
        Qt::NetworkAuth
        Qt::NetworkAuthPrivate
    TESTDATA ${test_data}
)

