//
//  main.swift
//  PacketTunnel
//
//  Created by 권정빈 on 2/11/26.
//

import Foundation
import NetworkExtension

#if os(macOS)
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
#endif
