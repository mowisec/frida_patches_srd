"""Kernel and TXM patches for running Frida on an iOS 27 research device.

    arm64/       the masked instruction vocabulary patterns are written in
    macho/       reading a firmware image and locating a site in it
    patch.py     what a patch IS: a named set of sites, and how they are applied
    patches/     the patches themselves, one module per patch
    cli/         the patch_kernel / patch_txm command lines
"""
