"""
Hilfsfunktionen für Zeitmessung und weitere Aufgaben.
Diese Datei ist betriebssystemunabhängig und funktioniert sowohl unter Linux als auch unter Windows.
"""

import time

def get_time():
    return int(time.time())
