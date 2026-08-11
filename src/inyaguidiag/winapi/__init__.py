"""Capa de compatibilidad con la API de Windows (7 a 11).

Aisla todo lo que cambia entre versiones de Windows: acceso a WMI,
privilegios, deteccion de WinPE. El resto del codigo no debe llamar a
subprocess ni a ctypes por su cuenta.
"""
