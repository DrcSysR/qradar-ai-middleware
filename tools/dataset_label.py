"""Детермінована розмітка унікальних випадків ai_dataset.db (мітки Claude, без Vertex).

Запуск (локально, на знімку БД):  python3 tools/dataset_label.py ai_dataset_snapshot.db labels.json
Пише JSON [[ukey, "close|benign", reason], ...] ЛИШЕ для рядків з claude_label IS NULL; у БД записує окремий крок
(UPDATE ... WHERE claude_label IS NULL, від користувача qmiddleware). human_label не чіпає.
Мітки: close|benign, close|insufficient_data (діапазон 0.4-0.6 рубрики), review|suspicious (ГІПОТЕЗА, не знахідка).
Це правила, а не незалежна експертиза: збіг з вердиктами моделі (99%) частково тавтологічний.
LK — таблиця перевірених рядків ін'єкцій (injector, injector_path, target_path, target_proc) -> (S|U|B, причина);
нові рядки, яких немає в LK, отримують U «not in reviewed table» і мають бути розглянуті вручну.
"""
import ast, collections, json, re, sqlite3, sys, zlib
sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))
from ai_dataset import norm_value

LK = {('#-csinstallerservice.exe', 'c:\\windows\\system#\\drivers\\crowdstrike\\#-csinstallerservice.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                       'known app, '
                                                                                                                                       'target not '
                                                                                                                                       'resolved '
                                                                                                                                       '(typical of '
                                                                                                                                       'benign '
                                                                                                                                       'self/child '
                                                                                                                                       'threads)'),
 ('#cestart.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\#cv#_x#\\common\\#cestart.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                              'known app, target not '
                                                                                                                              'resolved (typical of '
                                                                                                                              'benign self/child '
                                                                                                                              'threads)'),
 ('#cv#.exe', 'c:\\program files (x#)\\#cv#\\#.#.#.#\\bin\\#cv#.exe', 'c:\\program files (x#)\\microsoft\\edge\\application\\msedge.exe', 'msedge.exe'): ('B',
                                                                                                                                                          'cross-process '
                                                                                                                                                          'thread '
                                                                                                                                                          'between '
                                                                                                                                                          'known '
                                                                                                                                                          'system/app '
                                                                                                                                                          'binaries '
                                                                                                                                                          '(#cv#.exe->msedge.exe)'),
 ('#cv#.exe', 'c:\\program files (x#)\\#cv#\\#.#.#.#\\bin\\#cv#.exe', 'c:\\program files\\adobe\\acrobat dc\\acrobat\\acrobat.exe', 'acrobat.exe'): ('B',
                                                                                                                                                     'cross-process '
                                                                                                                                                     'thread '
                                                                                                                                                     'between '
                                                                                                                                                     'known '
                                                                                                                                                     'system/app '
                                                                                                                                                     'binaries '
                                                                                                                                                     '(#cv#.exe->acrobat.exe)'),
 ('#cv#.exe', 'c:\\program files (x#)\\#cv#\\#.#.#.#\\bin\\#cv#.exe', 'c:\\windows\\splwow#.exe', 'splwow#.exe'): ('B',
                                                                                                                   'cross-process thread between '
                                                                                                                   'known system/app binaries '
                                                                                                                   '(#cv#.exe->splwow#.exe)'),
 ('#cv#.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\#cv#_x#\\#.#.#.#\\bin\\#cv#.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                            'known app, target not '
                                                                                                                            'resolved (typical of '
                                                                                                                            'benign self/child '
                                                                                                                            'threads)'),
 ('#cv#c.exe', 'c:\\program files (x#)\\#cv#\\#.#.#.#\\bin\\#cv#c.exe', 'c:\\program files (x#)\\microsoft\\edge\\application\\msedge.exe', 'msedge.exe'): ('B',
                                                                                                                                                            'cross-process '
                                                                                                                                                            'thread '
                                                                                                                                                            'between '
                                                                                                                                                            'known '
                                                                                                                                                            'system/app '
                                                                                                                                                            'binaries '
                                                                                                                                                            '(#cv#c.exe->msedge.exe)'),
 ('#cv#c.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\#cv#_x#\\#.#.#.#\\bin\\#cv#c.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                              'known app, target not '
                                                                                                                              'resolved (typical of '
                                                                                                                              'benign self/child '
                                                                                                                              'threads)'),
 ('#cv#c.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\#cv#_x#\\#.#.#.#\\bin\\#cv#c.exe', 'c:\\program files (x#)\\microsoft\\edge\\application\\msedge.exe', 'msedge.exe'): ('B',
                                                                                                                                                                                 'cross-process '
                                                                                                                                                                                 'thread '
                                                                                                                                                                                 'between '
                                                                                                                                                                                 'known '
                                                                                                                                                                                 'system/app '
                                                                                                                                                                                 'binaries '
                                                                                                                                                                                 '(#cv#c.exe->msedge.exe)'),
 ('#cv#s.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\#cv#_x#\\#.#.#.#\\bin\\#cv#s.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                              'known app, target not '
                                                                                                                              'resolved (typical of '
                                                                                                                              'benign self/child '
                                                                                                                              'threads)'),
 ('#d#e#fbf#af#a#f#bf#e#_personal_office_i#n_free.exe.#.#.exe', 'c:\\programdata\\wps\\installers\\#d#e#fbf#af#a#f#bf#e#_personal_office_i#n_free.exe.#.#.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                                 'known '
                                                                                                                                                                                                 'app, '
                                                                                                                                                                                                 'target '
                                                                                                                                                                                                 'not '
                                                                                                                                                                                                 'resolved '
                                                                                                                                                                                                 '(typical '
                                                                                                                                                                                                 'of '
                                                                                                                                                                                                 'benign '
                                                                                                                                                                                                 'self/child '
                                                                                                                                                                                                 'threads)'),
 ('#dexperiencelaunchersystray.exe', 'c:\\program files\\dassault systemes\\#dexperience launcher\\#dexperiencelaunchersystray.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                      'known '
                                                                                                                                                                      'app, '
                                                                                                                                                                      'target '
                                                                                                                                                                      'not '
                                                                                                                                                                      'resolved '
                                                                                                                                                                      '(typical '
                                                                                                                                                                      'of '
                                                                                                                                                                      'benign '
                                                                                                                                                                      'self/child '
                                                                                                                                                                      'threads)'),
 ('#install-win.exe', 'c:\\users\\<u>\\appdata\\roaming\\programs\\zero install\\#install-win.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                     'known app, '
                                                                                                                                     'target not '
                                                                                                                                     'resolved '
                                                                                                                                     '(typical of '
                                                                                                                                     'benign '
                                                                                                                                     'self/child '
                                                                                                                                     'threads)'),
 ('?', '&lt;unknown process&gt;', '&lt;unknown process&gt;', ''): ('U', 'unknown->unknown'),
 ('?', '&lt;unknown process&gt;', 'c:\\program files (x#)\\microsoft\\edge\\application\\msedge.exe', 'msedge.exe'): ('U',
                                                                                                                      'unknown injector -> '
                                                                                                                      'msedge.exe (injector not '
                                                                                                                      'recorded)'),
 ('?', '&lt;unknown process&gt;', 'c:\\program files (x#)\\microsoft\\edgewebview\\application\\#.#.#.#\\msedgewebview#.exe', 'msedgewebview#.exe'): ('U',
                                                                                                                                                      'unknown '
                                                                                                                                                      'injector '
                                                                                                                                                      '-> '
                                                                                                                                                      'msedgewebview#.exe '
                                                                                                                                                      '(injector '
                                                                                                                                                      'not '
                                                                                                                                                      'recorded)'),
 ('?', '&lt;unknown process&gt;', 'c:\\program files\\google\\chrome\\application\\chrome.exe', 'chrome.exe'): ('U',
                                                                                                                'unknown injector -> chrome.exe '
                                                                                                                '(injector not recorded)'),
 ('?', '&lt;unknown process&gt;', 'c:\\program files\\oracle\\virtualbox\\virtualboxvm.exe', 'virtualboxvm.exe'): ('U',
                                                                                                                   'unknown injector -> '
                                                                                                                   'virtualboxvm.exe (injector not '
                                                                                                                   'recorded)'),
 ('?', '&lt;unknown process&gt;', 'c:\\users\\<u>\\.local\\bin\\claude.exe', 'claude.exe'): ('U',
                                                                                             'unknown injector -> claude.exe (injector not '
                                                                                             'recorded)'),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('U', 'unknown->cmd'),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\system#\\csrss.exe', 'csrss.exe'): ('S',
                                                                                    "невідомий інжектор->csrss.exe: ін'єкція в системний процес"),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\system#\\defrag.exe', 'defrag.exe'): ('U', 'unknown->defrag'),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\system#\\dllhost.exe', 'dllhost.exe'): ('U', 'unknown->dllhost'),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\system#\\driverstore\\filerepository\\snapo#.inf_amd#_#d#b#b#\\snapos#.exe', 'snapos#.exe'): ('U',
                                                                                                                                              'unknown->snapos'),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\system#\\dsregcmd.exe', 'dsregcmd.exe'): ('U', 'unknown->dsregcmd'),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\system#\\rundll#.exe', 'rundll#.exe'): ('U', 'unknown->rundll32'),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\system#\\sc.exe', 'sc.exe'): ('U', 'unknown->sc.exe'),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\system#\\srtasks.exe', 'srtasks.exe'): ('U', 'unknown->srtasks'),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\system#\\svchost.exe', 'svchost.exe'): ('U', 'unknown->svchost'),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\system#\\wbem\\wmiprvse.exe', 'wmiprvse.exe'): ('U', 'unknown->wmiprvse'),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\system#\\windowspowershell\\v#.#\\powershell.exe', 'powershell.exe'): ('U', 'unknown->powershell'),
 ('?', '&lt;unknown process&gt;', 'c:\\windows\\temp\\dptf\\esif_assist_#.exe', 'esif_assist_#.exe'): ('U',
                                                                                                       'unknown injector -> esif_assist_#.exe '
                                                                                                       '(injector not recorded)'),
 ('acadlt.exe', 'c:\\program files\\autodesk\\autocad lt #\\acadlt.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                          'known app, target not resolved (typical '
                                                                                                          'of benign self/child threads)'),
 ('acerccagent.exe', 'c:\\windows\\system#\\acerccagent.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                               'known app, target not resolved (typical of benign '
                                                                                               'self/child threads)'),
 ('acerqaagent.exe', 'c:\\windows\\system#\\acerqaagent.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                               'known app, target not resolved (typical of benign '
                                                                                               'self/child threads)'),
 ('acerservice.exe', 'c:\\windows\\system#\\driverstore\\filerepository\\acerservicecomponent.inf_amd#_c#ec#fd#cdf\\acerservice.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                       'known '
                                                                                                                                                                       'app, '
                                                                                                                                                                       'target '
                                                                                                                                                                       'not '
                                                                                                                                                                       'resolved '
                                                                                                                                                                       '(typical '
                                                                                                                                                                       'of '
                                                                                                                                                                       'benign '
                                                                                                                                                                       'self/child '
                                                                                                                                                                       'threads)'),
 ('acerservice.exe', 'c:\\windows\\system#\\driverstore\\filerepository\\acerservicecomponent.inf_amd#_c#ec#fd#cdf\\acerservice.exe', 'c:\\windows\\system#\\windowspowershell\\v#.#\\powershell.exe', 'powershell.exe'): ('U',
                                                                                                                                                                                                                           'OEM/vendor '
                                                                                                                                                                                                                           'service '
                                                                                                                                                                                                                           '-> '
                                                                                                                                                                                                                           'shell '
                                                                                                                                                                                                                           '(command '
                                                                                                                                                                                                                           'line '
                                                                                                                                                                                                                           'unseen)'),
 ('acrobat.exe', 'c:\\program files\\adobe\\acrobat dc\\acrobat\\acrobat.exe', 'c:\\program files\\adobe\\acrobat dc\\acrobat\\acrobat.exe', 'acrobat.exe'): ('B',
                                                                                                                                                              'self-injection '
                                                                                                                                                              'into '
                                                                                                                                                              'same '
                                                                                                                                                              'binary '
                                                                                                                                                              '(app '
                                                                                                                                                              'updater/sandbox)'),
 ('adobecollabsync.exe', 'c:\\program files (x#)\\adobe\\acrobat reader dc\\reader\\adobecollabsync.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                           'known '
                                                                                                                                           'app, '
                                                                                                                                           'target '
                                                                                                                                           'not '
                                                                                                                                           'resolved '
                                                                                                                                           '(typical '
                                                                                                                                           'of '
                                                                                                                                           'benign '
                                                                                                                                           'self/child '
                                                                                                                                           'threads)'),
 ('adobecollabsync.exe', 'c:\\program files\\adobe\\acrobat dc\\acrobat\\adobecollabsync.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                'known app, target '
                                                                                                                                'not resolved '
                                                                                                                                '(typical of benign '
                                                                                                                                'self/child '
                                                                                                                                'threads)'),
 ('agsrunner.bin', 'c:\\users\\<u>\\appdata\\local\\intel\\ags\\libs\\agsrunner.bin', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                       'known app, target not '
                                                                                                                       'resolved (typical of benign '
                                                                                                                       'self/child threads)'),
 ('anydesk-#-#-#.exe', 'd:\\downloads\\anydesk-#-#-#.exe', '&lt;unknown process&gt;', ''): ('U', 'anydesk з Downloads (некерований RAT)'),
 ('apihelper.exe', 'c:\\program files (x#)\\google\\endpoint verification\\apihelper.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                            'known app, target not '
                                                                                                                            'resolved (typical of '
                                                                                                                            'benign self/child '
                                                                                                                            'threads)'),
 ('arccontrolassist.exe', 'c:\\program files\\intel\\intel arc control\\arccontrolassist.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                'known app, target '
                                                                                                                                'not resolved '
                                                                                                                                '(typical of benign '
                                                                                                                                'self/child '
                                                                                                                                'threads)'),
 ('assistant_installer.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\.opera\\<guid> opera installer temp\\opera_package_#\\assistant\\assistant_installer.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                                'known '
                                                                                                                                                                                                'app, '
                                                                                                                                                                                                'target '
                                                                                                                                                                                                'not '
                                                                                                                                                                                                'resolved '
                                                                                                                                                                                                '(typical '
                                                                                                                                                                                                'of '
                                                                                                                                                                                                'benign '
                                                                                                                                                                                                'self/child '
                                                                                                                                                                                                'threads)'),
 ('assistant_installer.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\.opera\\<hex>\\cuserssergiy.pilkevychappdatalocalprogramsoperagxassistant\\installing\\assistant_installer.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                                                      'known '
                                                                                                                                                                                                                      'app, '
                                                                                                                                                                                                                      'target '
                                                                                                                                                                                                                      'not '
                                                                                                                                                                                                                      'resolved '
                                                                                                                                                                                                                      '(typical '
                                                                                                                                                                                                                      'of '
                                                                                                                                                                                                                      'benign '
                                                                                                                                                                                                                      'self/child '
                                                                                                                                                                                                                      'threads)'),
 ('asusappservice.exe', 'c:\\windows\\system#\\driverstore\\filerepository\\asussci#.inf_amd#_#a#a#b#f#d\\asusappservice\\asusappservice.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                'known '
                                                                                                                                                                                'app, '
                                                                                                                                                                                'target '
                                                                                                                                                                                'not '
                                                                                                                                                                                'resolved '
                                                                                                                                                                                '(typical '
                                                                                                                                                                                'of '
                                                                                                                                                                                'benign '
                                                                                                                                                                                'self/child '
                                                                                                                                                                                'threads)'),
 ('asussoftwaremanager.exe', 'c:\\windows\\system#\\driverstore\\filerepository\\asussci#.inf_amd#_#a#a#b#f#d\\asussoftwaremanager\\asussoftwaremanager.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                               'known '
                                                                                                                                                                                               'app, '
                                                                                                                                                                                               'target '
                                                                                                                                                                                               'not '
                                                                                                                                                                                               'resolved '
                                                                                                                                                                                               '(typical '
                                                                                                                                                                                               'of '
                                                                                                                                                                                               'benign '
                                                                                                                                                                                               'self/child '
                                                                                                                                                                                               'threads)'),
 ('au_.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\wps\\~#b#e#\\au_.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                            'known app, target not resolved (typical '
                                                                                                            'of benign self/child threads)'),
 ('au_.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\wps\\~b#f#\\au_.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                           'known app, target not resolved (typical '
                                                                                                           'of benign self/child threads)'),
 ('auto-start.exe', 'c:\\users\\<u>\\appdata\\roaming\\#install.net\\desktop-integration\\stubs\\<hex>\\auto-start.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                          'known '
                                                                                                                                                          'app, '
                                                                                                                                                          'target '
                                                                                                                                                          'not '
                                                                                                                                                          'resolved '
                                                                                                                                                          '(typical '
                                                                                                                                                          'of '
                                                                                                                                                          'benign '
                                                                                                                                                          'self/child '
                                                                                                                                                          'threads)'),
 ('bash.exe', 'c:\\program files\\git\\usr\\bin\\bash.exe', 'c:\\windows\\system#\\windowspowershell\\v#.#\\powershell.exe', 'powershell.exe'): ('B',
                                                                                                                                                 'managed '
                                                                                                                                                 'agent '
                                                                                                                                                 'or '
                                                                                                                                                 'dev '
                                                                                                                                                 'tool '
                                                                                                                                                 'starting '
                                                                                                                                                 'shell'),
 ('bash.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\git\\usr\\bin\\bash.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\python\\python#\\python.exe', 'python.exe'): ('B',
                                                                                                                                                                            'cross-process '
                                                                                                                                                                            'thread '
                                                                                                                                                                            'between '
                                                                                                                                                                            'known '
                                                                                                                                                                            'system/app '
                                                                                                                                                                            'binaries '
                                                                                                                                                                            '(bash.exe->python.exe)'),
 ('bdcam_nonadmin.exe', 'c:\\program files (x#)\\bandicam\\bdcam_nonadmin.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                 'known app, target not resolved '
                                                                                                                 '(typical of benign self/child '
                                                                                                                 'threads)'),
 ('bimx.exe', 'c:\\program files\\graphisoft\\bimx desktop viewer\\bimx.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                               'known app, target not resolved '
                                                                                                               '(typical of benign self/child '
                                                                                                               'threads)'),
 ('bingwallpaper.exe', 'c:\\program files\\windowsapps\\microsoft.bingwallpaper_#.#.#.#_x#__#wekyb#d#bbwe\\bingwallpaper.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                'known '
                                                                                                                                                                'app, '
                                                                                                                                                                'target '
                                                                                                                                                                'not '
                                                                                                                                                                'resolved '
                                                                                                                                                                '(typical '
                                                                                                                                                                'of '
                                                                                                                                                                'benign '
                                                                                                                                                                'self/child '
                                                                                                                                                                'threads)'),
 ('bingwallpaperinstaller.exe', 'c:\\users\\<u>\\downloads\\bingwallpaperinstaller.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                          'known app, target not '
                                                                                                                          'resolved (typical of '
                                                                                                                          'benign self/child '
                                                                                                                          'threads)'),
 ('browser_assistant.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\opera\\assistant\\browser_assistant.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                 'known '
                                                                                                                                                 'app, '
                                                                                                                                                 'target '
                                                                                                                                                 'not '
                                                                                                                                                 'resolved '
                                                                                                                                                 '(typical '
                                                                                                                                                 'of '
                                                                                                                                                 'benign '
                                                                                                                                                 'self/child '
                                                                                                                                                 'threads)'),
 ('cdgs#-u#.exe', 'c:\\programdata\\corel\\downloads\\<hex>\\cdgs#-u#.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                             'known app, target not resolved '
                                                                                                             '(typical of benign self/child '
                                                                                                             'threads)'),
 ('cdgs#-u#.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\{<guid>}\\cdgs#-u#.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                   'known app, target not resolved '
                                                                                                                   '(typical of benign self/child '
                                                                                                                   'threads)'),
 ('chatgpt.exe', 'c:\\program files\\windowsapps\\openai.codex_#.#.#.#_x#__#p#nqsd#c#g#\\app\\chatgpt.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                             'known '
                                                                                                                                             'app, '
                                                                                                                                             'target '
                                                                                                                                             'not '
                                                                                                                                             'resolved '
                                                                                                                                             '(typical '
                                                                                                                                             'of '
                                                                                                                                             'benign '
                                                                                                                                             'self/child '
                                                                                                                                             'threads)'),
 ('chg_file.exe', 'c:\\programdata\\trumpf\\trutops\\cut\\macros\\chg_file.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                  'known app, target not resolved '
                                                                                                                  '(typical of benign self/child '
                                                                                                                  'threads)'),
 ('chg_file.exe', 'c:\\trumpf.net\\utils\\macros\\chg_file.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                  'known app, target not resolved (typical of benign '
                                                                                                  'self/child threads)'),
 ('chrome.exe', 'c:\\program files (x#)\\google\\chrome\\application\\chrome.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('U',
                                                                                                                                 'browser->cmd.exe: '
                                                                                                                                 'fleet-wide (60+ '
                                                                                                                                 'hosts, 1-5 events '
                                                                                                                                 'each in 7d), '
                                                                                                                                 'likely benign '
                                                                                                                                 'common behavior; '
                                                                                                                                 'command line not '
                                                                                                                                 'checked'),
 ('chrome.exe', 'c:\\program files\\google\\chrome\\application\\chrome.exe', 'c:\\program files\\google\\chrome\\application\\chrome.exe', 'chrome.exe'): ('B',
                                                                                                                                                            'self-injection '
                                                                                                                                                            'into '
                                                                                                                                                            'same '
                                                                                                                                                            'binary '
                                                                                                                                                            '(app '
                                                                                                                                                            'updater/sandbox)'),
 ('chrome.exe', 'c:\\program files\\google\\chrome\\application\\chrome.exe', 'c:\\users\\<u>\\appdata\\local\\kingsoft\\wps office\\#.#.#.#\\office#\\wps.exe', 'wps.exe'): ('B',
                                                                                                                                                                              'cross-process '
                                                                                                                                                                              'thread '
                                                                                                                                                                              'between '
                                                                                                                                                                              'known '
                                                                                                                                                                              'system/app '
                                                                                                                                                                              'binaries '
                                                                                                                                                                              '(chrome.exe->wps.exe)'),
 ('chrome.exe', 'c:\\program files\\google\\chrome\\application\\chrome.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('U',
                                                                                                                            'browser->cmd.exe: '
                                                                                                                            'fleet-wide (60+ hosts, '
                                                                                                                            '1-5 events each in 7d), '
                                                                                                                            'likely benign common '
                                                                                                                            'behavior; command line '
                                                                                                                            'not checked'),
 ('chrome.exe', 'c:\\program files\\google\\chrome\\application\\chrome.exe', 'c:\\windows\\system#\\ipconfig.exe', 'ipconfig.exe'): ('S',
                                                                                                                                      'chrome->ipconfig.exe: '
                                                                                                                                      'розвідка '
                                                                                                                                      'мережі з '
                                                                                                                                      'браузера'),
 ('chrome.exe', 'c:\\program files\\google\\chrome\\application\\chrome.exe', 'c:\\windows\\system#\\ntdll.dll', 'ntdll.dll'): ('S',
                                                                                                                                'chrome->ntdll.dll: '
                                                                                                                                'ціль-бібліотека, '
                                                                                                                                'нетипово'),
 ('chrome_proxy.exe', 'c:\\program files (x#)\\google\\chrome\\application\\chrome_proxy.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                'known app, target '
                                                                                                                                'not resolved '
                                                                                                                                '(typical of benign '
                                                                                                                                'self/child '
                                                                                                                                'threads)'),
 ('chrome_proxy.exe', 'c:\\program files\\google\\chrome\\application\\chrome_proxy.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                           'known app, target not '
                                                                                                                           'resolved (typical of '
                                                                                                                           'benign self/child '
                                                                                                                           'threads)'),
 ('claude.exe', 'c:\\program files\\windowsapps\\claude_#.#.#.#_x#__pzs#sxrjxfjjc\\app\\claude.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                      'known app, '
                                                                                                                                      'target not '
                                                                                                                                      'resolved '
                                                                                                                                      '(typical of '
                                                                                                                                      'benign '
                                                                                                                                      'self/child '
                                                                                                                                      'threads)'),
 ('claude.exe', 'c:\\users\\<u>\\.local\\bin\\claude.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                            'known app, target not resolved (typical of benign '
                                                                                            'self/child threads)'),
 ('claude.exe', 'c:\\users\\<u>\\.local\\bin\\claude.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('B',
                                                                                                         'managed agent or dev tool starting shell'),
 ('claude.exe', 'c:\\users\\<u>\\.vscode\\extensions\\anthropic.claude-code-#.#.#-win#-x#\\resources\\native-binary\\claude.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('B',
                                                                                                                                                                                'managed '
                                                                                                                                                                                'agent '
                                                                                                                                                                                'or '
                                                                                                                                                                                'dev '
                                                                                                                                                                                'tool '
                                                                                                                                                                                'starting '
                                                                                                                                                                                'shell'),
 ('claude.exe', 'c:\\users\\<u>\\.vscode\\extensions\\anthropic.claude-code-#.#.#-win#-x#\\resources\\native-binary\\claude.exe', 'c:\\windows\\system#\\windowspowershell\\v#.#\\powershell.exe', 'powershell.exe'): ('B',
                                                                                                                                                                                                                       'managed '
                                                                                                                                                                                                                       'agent '
                                                                                                                                                                                                                       'or '
                                                                                                                                                                                                                       'dev '
                                                                                                                                                                                                                       'tool '
                                                                                                                                                                                                                       'starting '
                                                                                                                                                                                                                       'shell'),
 ('claude.exe', 'c:\\users\\<u>\\appdata\\local\\anthropicclaude\\app-#.#.#\\claude.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                           'known app, target not '
                                                                                                                           'resolved (typical of '
                                                                                                                           'benign self/child '
                                                                                                                           'threads)'),
 ('claude.exe', 'c:\\users\\<u>\\appdata\\local\\anthropicclaude\\app-#.#.#\\claude.exe', 'c:\\users\\<u>\\appdata\\local\\anthropicclaude\\update.exe', 'update.exe'): ('B',
                                                                                                                                                                         'cross-process '
                                                                                                                                                                         'thread '
                                                                                                                                                                         'between '
                                                                                                                                                                         'known '
                                                                                                                                                                         'system/app '
                                                                                                                                                                         'binaries '
                                                                                                                                                                         '(claude.exe->update.exe)'),
 ('claude.exe', 'c:\\users\\<u>\\appdata\\local\\nvm\\v#.#.#\\node_modules\\@anthropic-ai\\claude-code\\bin\\claude.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                           'known '
                                                                                                                                                           'app, '
                                                                                                                                                           'target '
                                                                                                                                                           'not '
                                                                                                                                                           'resolved '
                                                                                                                                                           '(typical '
                                                                                                                                                           'of '
                                                                                                                                                           'benign '
                                                                                                                                                           'self/child '
                                                                                                                                                           'threads)'),
 ('claude.exe', 'c:\\users\\<u>\\appdata\\local\\nvm\\v#.#.#\\node_modules\\@anthropic-ai\\claude-code\\bin\\claude.exe', 'c:\\windows\\system#\\windowspowershell\\v#.#\\powershell.exe', 'powershell.exe'): ('B',
                                                                                                                                                                                                               'managed '
                                                                                                                                                                                                               'agent '
                                                                                                                                                                                                               'or '
                                                                                                                                                                                                               'dev '
                                                                                                                                                                                                               'tool '
                                                                                                                                                                                                               'starting '
                                                                                                                                                                                                               'shell'),
 ('cmd.exe', 'c:\\windows\\system#\\cmd.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('B',
                                                                                            'self-injection into same binary (app updater/sandbox)'),
 ('cmd.exe', 'c:\\windows\\system#\\cmd.exe', 'c:\\windows\\system#\\windowspowershell\\v#.#\\powershell.exe', 'powershell.exe'): ('B',
                                                                                                                                   'managed agent or '
                                                                                                                                   'dev tool '
                                                                                                                                   'starting shell'),
 ('cmd.exe', 'c:\\windows\\syswow#\\cmd.exe', '&lt;unknown process&gt;', ''): ('U', 'syswow64 cmd->unknown'),
 ('code.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\microsoft vs code\\code.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                        'known app, target not '
                                                                                                                        'resolved (typical of benign '
                                                                                                                        'self/child threads)'),
 ('code.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\microsoft vs code\\code.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('B',
                                                                                                                                     'managed agent '
                                                                                                                                     'or dev tool '
                                                                                                                                     'starting '
                                                                                                                                     'shell'),
 ('codesetup-stable-<hex>.tmp', 'c:\\users\\<u>\\appdata\\local\\temp\\is-#ddu.tmp\\codesetup-stable-<hex>.tmp', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                  'known '
                                                                                                                                                  'app, '
                                                                                                                                                  'target '
                                                                                                                                                  'not '
                                                                                                                                                  'resolved '
                                                                                                                                                  '(typical '
                                                                                                                                                  'of '
                                                                                                                                                  'benign '
                                                                                                                                                  'self/child '
                                                                                                                                                  'threads)'),
 ('codex.exe', 'c:\\program files\\windowsapps\\openai.codex_#.#.#.#_x#__#p#nqsd#c#g#\\app\\resources\\codex.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                    'known '
                                                                                                                                                    'app, '
                                                                                                                                                    'target '
                                                                                                                                                    'not '
                                                                                                                                                    'resolved '
                                                                                                                                                    '(typical '
                                                                                                                                                    'of '
                                                                                                                                                    'benign '
                                                                                                                                                    'self/child '
                                                                                                                                                    'threads)'),
 ('codex.exe', 'c:\\users\\<u>\\appdata\\local\\openai\\codex\\bin\\<hex>\\codex.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                        'known app, target not '
                                                                                                                        'resolved (typical of benign '
                                                                                                                        'self/child threads)'),
 ('compattelrunner.exe', 'c:\\windows\\system#\\compattelrunner.exe', 'c:\\windows\\system#\\windowspowershell\\v#.#\\powershell.exe', 'powershell.exe'): ('B',
                                                                                                                                                           'managed '
                                                                                                                                                           'agent '
                                                                                                                                                           'or '
                                                                                                                                                           'dev '
                                                                                                                                                           'tool '
                                                                                                                                                           'starting '
                                                                                                                                                           'shell'),
 ('credentialuibroker.exe', 'c:\\windows\\system#\\credentialuibroker.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                             'known app, target not resolved '
                                                                                                             '(typical of benign self/child '
                                                                                                             'threads)'),
 ('csfalconservice.exe', 'c:\\program files\\crowdstrike\\csfalconservice.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                 'known app, target not resolved '
                                                                                                                 '(typical of benign self/child '
                                                                                                                 'threads)'),
 ('cut.exe', 'c:\\program files\\trumpf\\trutops\\cut\\bin\\cut.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                       'known app, target not resolved (typical of '
                                                                                                       'benign self/child threads)'),
 ('cutting#.exe', 'd:\\_programs\\cutting # #.#\\cutting#.exe', 'c:\\windows\\splwow#.exe', 'splwow#.exe'): ('B',
                                                                                                             'cross-process thread between known '
                                                                                                             'system/app binaries '
                                                                                                             '(cutting#.exe->splwow#.exe)'),
 ('dax#api.exe', 'c:\\windows\\system#\\dolbyaposvc\\dax#api.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                    'known app, target not resolved (typical of '
                                                                                                    'benign self/child threads)'),
 ('declplus.exe', 'c:\\masterd\\md-declaration\\declplus.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                'known app, target not resolved (typical of benign '
                                                                                                'self/child threads)'),
 ('deepl.exe', 'c:\\users\\<u>\\appdata\\local\\#install.net\\implementations\\sha#new_zbs#pbjqxquof#qzxke#mft#pqudb#zwkcizjrvfi#opvdttvx#a\\deepl.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                          'known '
                                                                                                                                                                                          'app, '
                                                                                                                                                                                          'target '
                                                                                                                                                                                          'not '
                                                                                                                                                                                          'resolved '
                                                                                                                                                                                          '(typical '
                                                                                                                                                                                          'of '
                                                                                                                                                                                          'benign '
                                                                                                                                                                                          'self/child '
                                                                                                                                                                                          'threads)'),
 ('default-browser-agent.exe', 'c:\\program files (x#)\\mozilla firefox\\default-browser-agent.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                      'known app, '
                                                                                                                                      'target not '
                                                                                                                                      'resolved '
                                                                                                                                      '(typical of '
                                                                                                                                      'benign '
                                                                                                                                      'self/child '
                                                                                                                                      'threads)'),
 ('default-browser-agent.exe', 'c:\\program files\\mozilla firefox\\default-browser-agent.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                 'known app, target '
                                                                                                                                 'not resolved '
                                                                                                                                 '(typical of benign '
                                                                                                                                 'self/child '
                                                                                                                                 'threads)'),
 ('default-browser-agent.exe', 'c:\\users\\<u>\\appdata\\local\\mozilla firefox\\default-browser-agent.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                              'known '
                                                                                                                                              'app, '
                                                                                                                                              'target '
                                                                                                                                              'not '
                                                                                                                                              'resolved '
                                                                                                                                              '(typical '
                                                                                                                                              'of '
                                                                                                                                              'benign '
                                                                                                                                              'self/child '
                                                                                                                                              'threads)'),
 ('diff_i#n_#.#.#.#_unified_to_#.#.#.#_unified.exe', 'c:\\users\\<u>\\appdata\\roaming\\kingsoft\\office#\\update\\down\\diff_i#n_#.#.#.#_unified_to_#.#.#.#_unified.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                                            'known '
                                                                                                                                                                                                            'app, '
                                                                                                                                                                                                            'target '
                                                                                                                                                                                                            'not '
                                                                                                                                                                                                            'resolved '
                                                                                                                                                                                                            '(typical '
                                                                                                                                                                                                            'of '
                                                                                                                                                                                                            'benign '
                                                                                                                                                                                                            'self/child '
                                                                                                                                                                                                            'threads)'),
 ('dim.exe', 'c:\\program files\\corel\\pasmutility\\v#\\dim.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                    'known app, target not resolved (typical of '
                                                                                                    'benign self/child threads)'),
 ('doublecmd.exe', 'd:\\програми\\doublecmd\\doublecmd.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                              'known app, target not resolved (typical of benign '
                                                                                              'self/child threads)'),
 ('download.exe', 'c:\\program files\\ocs inventory agent\\download.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                           'known app, target not resolved (typical '
                                                                                                           'of benign self/child threads)'),
 ('e_tinvlve.exe', 'c:\\windows\\system#\\spool\\drivers\\x#\\#\\e_tinvlve.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                  'known app, target not resolved '
                                                                                                                  '(typical of benign self/child '
                                                                                                                  'threads)'),
 ('elanfpservice.exe', 'c:\\windows\\system#\\elanfpservice.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                   'known app, target not resolved (typical of '
                                                                                                   'benign self/child threads)'),
 ('eppccmon.exe', 'c:\\program files (x#)\\epson software\\epson printer connection checker\\eppccmon.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                             'known '
                                                                                                                                             'app, '
                                                                                                                                             'target '
                                                                                                                                             'not '
                                                                                                                                             'resolved '
                                                                                                                                             '(typical '
                                                                                                                                             'of '
                                                                                                                                             'benign '
                                                                                                                                             'self/child '
                                                                                                                                             'threads)'),
 ('et.exe', 'c:\\users\\<u>\\appdata\\local\\kingsoft\\wps office\\#.#.#.#\\office#\\et.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                               'known app, target '
                                                                                                                               'not resolved '
                                                                                                                               '(typical of benign '
                                                                                                                               'self/child threads)'),
 ('excel.exe', 'c:\\program files\\microsoft office\\office#\\excel.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                           'known app, target not resolved (typical '
                                                                                                           'of benign self/child threads)'),
 ('excel.exe', 'c:\\program files\\microsoft office\\office#\\excel.exe', 'c:\\program files\\microsoft office\\office#\\excel.exe', 'excel.exe'): ('B',
                                                                                                                                                    'self-injection '
                                                                                                                                                    'into '
                                                                                                                                                    'same '
                                                                                                                                                    'binary '
                                                                                                                                                    '(app '
                                                                                                                                                    'updater/sandbox)'),
 ('excel.exe', 'c:\\program files\\microsoft office\\root\\office#\\excel.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                 'known app, target not resolved '
                                                                                                                 '(typical of benign self/child '
                                                                                                                 'threads)'),
 ('excel.exe', 'c:\\progra~#\\micros~#\\office#\\excel.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                              'known app, target not resolved (typical of benign '
                                                                                              'self/child threads)'),
 ('explorer.exe', 'c:\\windows\\explorer.exe', 'c:\\program files\\google\\chrome\\application\\chrome.exe', 'chrome.exe'): ('B',
                                                                                                                             'cross-process thread '
                                                                                                                             'between known '
                                                                                                                             'system/app binaries '
                                                                                                                             '(explorer.exe->chrome.exe)'),
 ('explorer.exe', 'c:\\windows\\explorer.exe', 'c:\\windows\\system#\\mstsc.exe', 'mstsc.exe'): ('B',
                                                                                                 'cross-process thread between known system/app '
                                                                                                 'binaries (explorer.exe->mstsc.exe)'),
 ('ezvit.exe', '\\\\medocnew\\medocsrv\\ezvit.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                     'known app, target not resolved (typical of benign self/child '
                                                                                     'threads)'),
 ('ezvit.exe', 'c:\\program files\\medoc\\medoc\\ezvit.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                              'known app, target not resolved (typical of benign '
                                                                                              'self/child threads)'),
 ('firefox.exe', 'c:\\users\\<u>\\appdata\\local\\mozilla firefox\\firefox.exe', 'c:\\users\\<u>\\appdata\\local\\mozilla firefox\\firefox.exe', 'firefox.exe'): ('B',
                                                                                                                                                                  'self-injection '
                                                                                                                                                                  'into '
                                                                                                                                                                  'same '
                                                                                                                                                                  'binary '
                                                                                                                                                                  '(app '
                                                                                                                                                                  'updater/sandbox)'),
 ('firefox.exe', 'd:\\temp\\mozilla\\firefoxportable\\app\\firefox#\\firefox.exe', '&lt;unknown process&gt;', ''): ('U',
                                                                                                                    'firefoxportable з d:\\temp'),
 ('forfiles.exe', 'c:\\windows\\system#\\forfiles.exe', '&lt;unknown process&gt;', ''): ('U', 'forfiles як інжектор'),
 ('foxitreader.exe', 'c:\\program files (x#)\\foxit software\\foxit reader\\foxitreader.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                               'known app, target '
                                                                                                                               'not resolved '
                                                                                                                               '(typical of benign '
                                                                                                                               'self/child threads)'),
 ('freecommander.exe', 'd:\\install\\freecommanderportable\\app\\freecommanderxe\\freecommander.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                       'known app, '
                                                                                                                                       'target not '
                                                                                                                                       'resolved '
                                                                                                                                       '(typical of '
                                                                                                                                       'benign '
                                                                                                                                       'self/child '
                                                                                                                                       'threads)'),
 ('gigabyteupdateservice.exe', 'c:\\windows\\system#\\gigabyteupdateservice.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                   'known app, target not resolved '
                                                                                                                   '(typical of benign self/child '
                                                                                                                   'threads)'),
 ('gigabyteupdateservice.exe', 'c:\\windows\\system#\\gigabyteupdateservice.exe', 'c:\\windows\\system#\\gigabytedownloadassistant.exe', 'gigabytedownloadassistant.exe'): ('U',
                                                                                                                                                                            'gigabyte->downloadassistant'),
 ('git.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\git\\mingw#\\libexec\\git-core\\git.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                   'known app, '
                                                                                                                                   'target not '
                                                                                                                                   'resolved '
                                                                                                                                   '(typical of '
                                                                                                                                   'benign '
                                                                                                                                   'self/child '
                                                                                                                                   'threads)'),
 ('googledrivefs.exe', 'c:\\program files\\google\\drive file stream\\<ip-ext>\\googledrivefs.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                     'known app, '
                                                                                                                                     'target not '
                                                                                                                                     'resolved '
                                                                                                                                     '(typical of '
                                                                                                                                     'benign '
                                                                                                                                     'self/child '
                                                                                                                                     'threads)'),
 ('gpscript.exe', 'c:\\windows\\system#\\gpscript.exe', 'c:\\windows\\system#\\windowspowershell\\v#.#\\powershell.exe', 'powershell.exe'): ('B',
                                                                                                                                             'managed '
                                                                                                                                             'agent '
                                                                                                                                             'or dev '
                                                                                                                                             'tool '
                                                                                                                                             'starting '
                                                                                                                                             'shell'),
 ('grammarly.desktop.exe', 'c:\\users\\<u>\\appdata\\local\\grammarly\\desktopintegrations\\grammarly.desktop.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                     'known '
                                                                                                                                                     'app, '
                                                                                                                                                     'target '
                                                                                                                                                     'not '
                                                                                                                                                     'resolved '
                                                                                                                                                     '(typical '
                                                                                                                                                     'of '
                                                                                                                                                     'benign '
                                                                                                                                                     'self/child '
                                                                                                                                                     'threads)'),
 ('grammarlyinstaller.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\grammarly.desktop\\grammarlyinstaller.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                'known '
                                                                                                                                                'app, '
                                                                                                                                                'target '
                                                                                                                                                'not '
                                                                                                                                                'resolved '
                                                                                                                                                '(typical '
                                                                                                                                                'of '
                                                                                                                                                'benign '
                                                                                                                                                'self/child '
                                                                                                                                                'threads)'),
 ('greenshot.exe', 'c:\\users\\<u>\\appdata\\local\\greenshot\\greenshot.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                'known app, target not resolved '
                                                                                                                '(typical of benign self/child '
                                                                                                                'threads)'),
 ('greenshot.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\greenshot\\greenshot.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                          'known app, target not '
                                                                                                                          'resolved (typical of '
                                                                                                                          'benign self/child '
                                                                                                                          'threads)'),
 ('hmark.exe', 'c:\\users\\<u>\\appdata\\local\\herelabel\\hmark.exe', '&lt;unknown process&gt;', ''): ('U',
                                                                                                        'unidentified binary in user-writable path'),
 ('hmark.exe', 'c:\\users\\<u>\\appdata\\local\\herelabel\\hmark.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('U', 'hmark->cmd'),
 ('hpaudioanalytics.exe', 'c:\\windows\\system#\\driverstore\\filerepository\\hpqkbsoftwarecompnent.inf_amd#_#d#a#e#\\hpaudioanalytics.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                              'known '
                                                                                                                                                                              'app, '
                                                                                                                                                                              'target '
                                                                                                                                                                              'not '
                                                                                                                                                                              'resolved '
                                                                                                                                                                              '(typical '
                                                                                                                                                                              'of '
                                                                                                                                                                              'benign '
                                                                                                                                                                              'self/child '
                                                                                                                                                                              'threads)'),
 ('hpaudioanalytics.exe', 'c:\\windows\\system#\\driverstore\\filerepository\\hpqkbsoftwarecompnent.inf_amd#_#d#a#e#\\hpaudioanalytics.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('U',
                                                                                                                                                                                           'OEM/vendor '
                                                                                                                                                                                           'service '
                                                                                                                                                                                           '-> '
                                                                                                                                                                                           'shell '
                                                                                                                                                                                           '(command '
                                                                                                                                                                                           'line '
                                                                                                                                                                                           'unseen)'),
 ('hpbcsiinstaller.exe', '\\\\modern.org\\soft\\public\\it_support\\driver\\printer drivers\\m#\\installer\\hpbcsiinstaller.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                   'known '
                                                                                                                                                                   'app, '
                                                                                                                                                                   'target '
                                                                                                                                                                   'not '
                                                                                                                                                                   'resolved '
                                                                                                                                                                   '(typical '
                                                                                                                                                                   'of '
                                                                                                                                                                   'benign '
                                                                                                                                                                   'self/child '
                                                                                                                                                                   'threads)'),
 ('hpbcsiinstaller.exe', 'c:\\program files (x#)\\hp\\csiinstaller\\<guid>\\installer\\hpbcsiinstaller.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                              'known '
                                                                                                                                              'app, '
                                                                                                                                              'target '
                                                                                                                                              'not '
                                                                                                                                              'resolved '
                                                                                                                                              '(typical '
                                                                                                                                              'of '
                                                                                                                                              'benign '
                                                                                                                                              'self/child '
                                                                                                                                              'threads)'),
 ('hpupdate.exe', 'c:\\program files (x#)\\hp\\hp support framework\\resources\\hpupdate\\hpupdate.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                          'known '
                                                                                                                                          'app, '
                                                                                                                                          'target '
                                                                                                                                          'not '
                                                                                                                                          'resolved '
                                                                                                                                          '(typical '
                                                                                                                                          'of benign '
                                                                                                                                          'self/child '
                                                                                                                                          'threads)'),
 ('i_view#.exe', 'c:\\program files\\windowsapps\\#irfanskiljanirfanvie.irfanview_#.#.#.#_x#__psgec#n#n#ne\\i_view#.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                           'known '
                                                                                                                                                           'app, '
                                                                                                                                                           'target '
                                                                                                                                                           'not '
                                                                                                                                                           'resolved '
                                                                                                                                                           '(typical '
                                                                                                                                                           'of '
                                                                                                                                                           'benign '
                                                                                                                                                           'self/child '
                                                                                                                                                           'threads)'),
 ('ie#uinit.exe', 'c:\\windows\\system#\\ie#uinit.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                         'known app, target not resolved (typical of benign '
                                                                                         'self/child threads)'),
 ('ie_to_edge_stub.exe', 'c:\\program files (x#)\\microsoft\\edge\\application\\#.#.#.#\\bho\\ie_to_edge_stub.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                     'known '
                                                                                                                                                     'app, '
                                                                                                                                                     'target '
                                                                                                                                                     'not '
                                                                                                                                                     'resolved '
                                                                                                                                                     '(typical '
                                                                                                                                                     'of '
                                                                                                                                                     'benign '
                                                                                                                                                     'self/child '
                                                                                                                                                     'threads)'),
 ('iexplore.exe', 'c:\\program files\\internet explorer\\iexplore.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                         'known app, target not resolved (typical of '
                                                                                                         'benign self/child threads)'),
 ('igfxcuiservice.exe', 'c:\\windows\\system#\\igfxcuiservice.exe', 'c:\\windows\\system#\\ntdll.dll', 'ntdll.dll'): ('U',
                                                                                                                      'igfxcuiservice->ntdll.dll'),
 ('installer.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\#zs#d#a#b#\\installer.exe', '&lt;unknown process&gt;', ''): ('U',
                                                                                                                       'unidentified binary in '
                                                                                                                       'user-writable path'),
 ('installer.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\.opera\\<hex>\\cusersalla.nykytiukappdatalocalprogramsopera\\installing\\installer.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                    'known '
                                                                                                                                                                                    'app, '
                                                                                                                                                                                    'target '
                                                                                                                                                                                    'not '
                                                                                                                                                                                    'resolved '
                                                                                                                                                                                    '(typical '
                                                                                                                                                                                    'of '
                                                                                                                                                                                    'benign '
                                                                                                                                                                                    'self/child '
                                                                                                                                                                                    'threads)'),
 ('installer.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\.opera\\<hex>\\cusersanna.zybinaappdatalocalprogramsopera\\installing\\installer.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                  'known '
                                                                                                                                                                                  'app, '
                                                                                                                                                                                  'target '
                                                                                                                                                                                  'not '
                                                                                                                                                                                  'resolved '
                                                                                                                                                                                  '(typical '
                                                                                                                                                                                  'of '
                                                                                                                                                                                  'benign '
                                                                                                                                                                                  'self/child '
                                                                                                                                                                                  'threads)'),
 ('installer.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\.opera\\<hex>\\cusersdmytro.karpukappdatalocalprogramsopera\\installing\\installer.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                    'known '
                                                                                                                                                                                    'app, '
                                                                                                                                                                                    'target '
                                                                                                                                                                                    'not '
                                                                                                                                                                                    'resolved '
                                                                                                                                                                                    '(typical '
                                                                                                                                                                                    'of '
                                                                                                                                                                                    'benign '
                                                                                                                                                                                    'self/child '
                                                                                                                                                                                    'threads)'),
 ('installer.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\.opera\\<hex>\\cusershalyna.baraboliukappdatalocalprogramsopera\\installing\\installer.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                        'known '
                                                                                                                                                                                        'app, '
                                                                                                                                                                                        'target '
                                                                                                                                                                                        'not '
                                                                                                                                                                                        'resolved '
                                                                                                                                                                                        '(typical '
                                                                                                                                                                                        'of '
                                                                                                                                                                                        'benign '
                                                                                                                                                                                        'self/child '
                                                                                                                                                                                        'threads)'),
 ('installer.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\.opera\\<hex>\\cusersmyroslav.dymarchukappdatalocalprogramsopera\\installing\\installer.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                         'known '
                                                                                                                                                                                         'app, '
                                                                                                                                                                                         'target '
                                                                                                                                                                                         'not '
                                                                                                                                                                                         'resolved '
                                                                                                                                                                                         '(typical '
                                                                                                                                                                                         'of '
                                                                                                                                                                                         'benign '
                                                                                                                                                                                         'self/child '
                                                                                                                                                                                         'threads)'),
 ('installer.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\.opera\\<hex>\\cusersnadiya.veremeychykappdatalocalprogramsopera\\installing\\installer.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                         'known '
                                                                                                                                                                                         'app, '
                                                                                                                                                                                         'target '
                                                                                                                                                                                         'not '
                                                                                                                                                                                         'resolved '
                                                                                                                                                                                         '(typical '
                                                                                                                                                                                         'of '
                                                                                                                                                                                         'benign '
                                                                                                                                                                                         'self/child '
                                                                                                                                                                                         'threads)'),
 ('installer.exe', 'c:\\users\\<u>\\appdata\\local\\temp\\.opera\\<hex>\\cusersvitaliy.navratyukappdatalocalprogramsopera\\installing\\installer.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                        'known '
                                                                                                                                                                                        'app, '
                                                                                                                                                                                        'target '
                                                                                                                                                                                        'not '
                                                                                                                                                                                        'resolved '
                                                                                                                                                                                        '(typical '
                                                                                                                                                                                        'of '
                                                                                                                                                                                        'benign '
                                                                                                                                                                                        'self/child '
                                                                                                                                                                                        'threads)'),
 ('intelgraphicssoftware.service.exe', 'c:\\program files\\windowsapps\\appup.intelarcsoftware_#.#.#.#_x#__#j#eq#eme#ctt\\vfs\\programfilesx#\\intel\\intel graphics software\\intelgraphicssoftware.service.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                                                                                    'known '
                                                                                                                                                                                                                                                    'app, '
                                                                                                                                                                                                                                                    'target '
                                                                                                                                                                                                                                                    'not '
                                                                                                                                                                                                                                                    'resolved '
                                                                                                                                                                                                                                                    '(typical '
                                                                                                                                                                                                                                                    'of '
                                                                                                                                                                                                                                                    'benign '
                                                                                                                                                                                                                                                    'self/child '
                                                                                                                                                                                                                                                    'threads)'),
 ('ivms-#.framework.s.exe', 'c:\\program files (x#)\\ivms-# site\\ivms-# client\\server\\ivms-#.framework.s.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                   'known '
                                                                                                                                                   'app, '
                                                                                                                                                   'target '
                                                                                                                                                   'not '
                                                                                                                                                   'resolved '
                                                                                                                                                   '(typical '
                                                                                                                                                   'of '
                                                                                                                                                   'benign '
                                                                                                                                                   'self/child '
                                                                                                                                                   'threads)'),
 ('ksomisc.exe', 'c:\\users\\<u>\\appdata\\local\\kingsoft\\wps office\\#.#.#.#\\office#\\ksomisc.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                         'known app, '
                                                                                                                                         'target not '
                                                                                                                                         'resolved '
                                                                                                                                         '(typical '
                                                                                                                                         'of benign '
                                                                                                                                         'self/child '
                                                                                                                                         'threads)'),
 ('ksomisc.exe', 'e:\\kingsoft\\wps office\\#.#.#.#\\office#\\ksomisc.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                             'known app, target not resolved '
                                                                                                             '(typical of benign self/child '
                                                                                                             'threads)'),
 ('kvpins#.exe', 'c:\\users\\<u>\\appdata\\local\\kingsoft\\wps office\\#.#.#.#\\office#\\kvprinter\\kvpins#.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                    'known '
                                                                                                                                                    'app, '
                                                                                                                                                    'target '
                                                                                                                                                    'not '
                                                                                                                                                    'resolved '
                                                                                                                                                    '(typical '
                                                                                                                                                    'of '
                                                                                                                                                    'benign '
                                                                                                                                                    'self/child '
                                                                                                                                                    'threads)'),
 ('lenovovantage-(lenovoproductivitysystemaddin).exe', 'c:\\program files (x#)\\lenovo\\vantageservice\\#.#.#.#\\lenovovantage-(lenovoproductivitysystemaddin).exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                                      'known '
                                                                                                                                                                                                      'app, '
                                                                                                                                                                                                      'target '
                                                                                                                                                                                                      'not '
                                                                                                                                                                                                      'resolved '
                                                                                                                                                                                                      '(typical '
                                                                                                                                                                                                      'of '
                                                                                                                                                                                                      'benign '
                                                                                                                                                                                                      'self/child '
                                                                                                                                                                                                      'threads)'),
 ('livecaptions.exe', 'c:\\windows\\system#\\livecaptions.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                 'known app, target not resolved (typical of benign '
                                                                                                 'self/child threads)'),
 ('logonui.exe', 'c:\\windows\\system#\\logonui.exe', 'c:\\windows\\system#\\rundll#.exe', 'rundll#.exe'): ('U', 'logonui->rundll32'),
 ('loom.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\loom\\loom.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                           'known app, target not resolved (typical '
                                                                                                           'of benign self/child threads)'),
 ('loqintel_vbioscheck.exe', 'c:\\programdata\\lenovo\\systemupdate\\sessionse\\repository\\loqamd#_vbiosupdate_#\\loqintel_vbioscheck.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                              'known '
                                                                                                                                                                              'app, '
                                                                                                                                                                              'target '
                                                                                                                                                                              'not '
                                                                                                                                                                              'resolved '
                                                                                                                                                                              '(typical '
                                                                                                                                                                              'of '
                                                                                                                                                                              'benign '
                                                                                                                                                                              'self/child '
                                                                                                                                                                              'threads)'),
 ('mastercam.exe', 'c:\\program files\\mcam#\\mastercam.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                               'known app, target not resolved (typical of benign '
                                                                                               'self/child threads)'),
 ('ms-teams.exe', 'c:\\program files\\windowsapps\\msteams_#.#.#.#_x#__#wekyb#d#bbwe\\ms-teams.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                      'known app, '
                                                                                                                                      'target not '
                                                                                                                                      'resolved '
                                                                                                                                      '(typical of '
                                                                                                                                      'benign '
                                                                                                                                      'self/child '
                                                                                                                                      'threads)'),
 ('msedge.exe', 'c:\\program files (x#)\\microsoft\\edge\\application\\msedge.exe', 'c:\\program files (x#)\\microsoft\\edge\\application\\msedge.exe', 'msedge.exe'): ('B',
                                                                                                                                                                        'self-injection '
                                                                                                                                                                        'into '
                                                                                                                                                                        'same '
                                                                                                                                                                        'binary '
                                                                                                                                                                        '(app '
                                                                                                                                                                        'updater/sandbox)'),
 ('msedge.exe', 'c:\\program files (x#)\\microsoft\\edge\\application\\msedge.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('U',
                                                                                                                                  'browser->cmd.exe: '
                                                                                                                                  'fleet-wide (60+ '
                                                                                                                                  'hosts, 1-5 events '
                                                                                                                                  'each in 7d), '
                                                                                                                                  'likely benign '
                                                                                                                                  'common behavior; '
                                                                                                                                  'command line not '
                                                                                                                                  'checked'),
 ('msiexec.exe', 'c:\\windows\\system#\\msiexec.exe', 'c:\\windows\\system#\\msiexec.exe', 'msiexec.exe'): ('B',
                                                                                                            'self-injection into same binary (app '
                                                                                                            'updater/sandbox)'),
 ('mspcmanagerservice.exe', 'c:\\program files\\windowsapps\\microsoft.microsoftpcmanager_#.#.#.#_x#__#wekyb#d#bbwe\\pcmanager\\mspcmanagerservice.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                          'known '
                                                                                                                                                                                          'app, '
                                                                                                                                                                                          'target '
                                                                                                                                                                                          'not '
                                                                                                                                                                                          'resolved '
                                                                                                                                                                                          '(typical '
                                                                                                                                                                                          'of '
                                                                                                                                                                                          'benign '
                                                                                                                                                                                          'self/child '
                                                                                                                                                                                          'threads)'),
 ('ncad.exe', 'c:\\program files (x#)\\nanosoft\\nanocad #.#\\ncad.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                          'known app, target not resolved (typical '
                                                                                                          'of benign self/child threads)'),
 ('ncexpress.exe', 'c:\\prima power\\ncexpress\\bin\\ncexpress.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                      'known app, target not resolved (typical of '
                                                                                                      'benign self/child threads)'),
 ('ncexpress.exe', 'c:\\prima power\\prima power\\ncexpress\\bin\\ncexpress.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                   'known app, target not resolved '
                                                                                                                   '(typical of benign self/child '
                                                                                                                   'threads)'),
 ('nginx.exe', 'c:\\program files (x#)\\ivms-# site\\nginx\\nginx.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                         'known app, target not resolved (typical of '
                                                                                                         'benign self/child threads)'),
 ('node.exe', 'c:\\program files\\adobe\\adobe creative cloud experience\\libs\\node.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                            'known app, target not '
                                                                                                                            'resolved (typical of '
                                                                                                                            'benign self/child '
                                                                                                                            'threads)'),
 ('node.exe', 'c:\\users\\<u>\\appdata\\local\\nvm\\v#.#.#\\node.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('B',
                                                                                                                     'managed agent or dev tool '
                                                                                                                     'starting shell'),
 ('node.exe', 'c:\\users\\<u>\\appdata\\roaming\\nvm\\v#.#.#\\node.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('B',
                                                                                                                       'managed agent or dev tool '
                                                                                                                       'starting shell'),
 ('node.exe', 'd:\\nodejs\\node.exe', '&lt;unknown process&gt;', ''): ('B', 'known app, target not resolved (typical of benign self/child threads)'),
 ('notification_helper.exe', 'c:\\program files (x#)\\microsoft\\edge\\application\\#.#.#.#\\notification_helper.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                        'known '
                                                                                                                                                        'app, '
                                                                                                                                                        'target '
                                                                                                                                                        'not '
                                                                                                                                                        'resolved '
                                                                                                                                                        '(typical '
                                                                                                                                                        'of '
                                                                                                                                                        'benign '
                                                                                                                                                        'self/child '
                                                                                                                                                        'threads)'),
 ('nvcontainer.exe', 'c:\\program files\\nvidia corporation\\nvcontainer\\nvcontainer.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                             'known app, target not '
                                                                                                                             'resolved (typical of '
                                                                                                                             'benign self/child '
                                                                                                                             'threads)'),
 ('nvdisplay.container.exe', 'c:\\program files\\nvidia corporation\\display.nvcontainer\\nvdisplay.container.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                     'known '
                                                                                                                                                     'app, '
                                                                                                                                                     'target '
                                                                                                                                                     'not '
                                                                                                                                                     'resolved '
                                                                                                                                                     '(typical '
                                                                                                                                                     'of '
                                                                                                                                                     'benign '
                                                                                                                                                     'self/child '
                                                                                                                                                     'threads)'),
 ('nvvsvc.exe', 'c:\\windows\\system#\\nvvsvc.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                     'known app, target not resolved (typical of benign self/child '
                                                                                     'threads)'),
 ('nvxdsync.exe', 'c:\\program files\\nvidia corporation\\display\\nvxdsync.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                   'known app, target not resolved '
                                                                                                                   '(typical of benign self/child '
                                                                                                                   'threads)'),
 ('ocsinventory.exe', 'c:\\program files\\ocs inventory agent\\ocsinventory.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('B',
                                                                                                                                'managed agent or '
                                                                                                                                'dev tool starting '
                                                                                                                                'shell'),
 ('openvpnconnect.exe', 'c:\\program files\\openvpn connect\\openvpnconnect.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                   'known app, target not resolved '
                                                                                                                   '(typical of benign self/child '
                                                                                                                   'threads)'),
 ('openwith.exe', 'c:\\windows\\system#\\openwith.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                         'known app, target not resolved (typical of benign '
                                                                                         'self/child threads)'),
 ('opera.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\opera\\opera.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\opera\\opera.exe', 'opera.exe'): ('B',
                                                                                                                                                          'self-injection '
                                                                                                                                                          'into '
                                                                                                                                                          'same '
                                                                                                                                                          'binary '
                                                                                                                                                          '(app '
                                                                                                                                                          'updater/sandbox)'),
 ('opera_autoupdate.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\opera gx\\autoupdate\\opera_autoupdate.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                   'known '
                                                                                                                                                   'app, '
                                                                                                                                                   'target '
                                                                                                                                                   'not '
                                                                                                                                                   'resolved '
                                                                                                                                                   '(typical '
                                                                                                                                                   'of '
                                                                                                                                                   'benign '
                                                                                                                                                   'self/child '
                                                                                                                                                   'threads)'),
 ('opera_autoupdate.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\opera\\autoupdate\\opera_autoupdate.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                'known '
                                                                                                                                                'app, '
                                                                                                                                                'target '
                                                                                                                                                'not '
                                                                                                                                                'resolved '
                                                                                                                                                '(typical '
                                                                                                                                                'of '
                                                                                                                                                'benign '
                                                                                                                                                'self/child '
                                                                                                                                                'threads)'),
 ('optiplan.exe', 'c:\\biesse\\optiplanning\\system\\optiplan.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                     'known app, target not resolved (typical of '
                                                                                                     'benign self/child threads)'),
 ('oscript.exe', 'e:\\onescript\\bin\\oscript.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('U', 'oscript->cmd'),
 ('pangpa.exe', 'c:\\program files\\palo alto networks\\globalprotect\\pangpa.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                     'known app, target not resolved '
                                                                                                                     '(typical of benign self/child '
                                                                                                                     'threads)'),
 ('pangphip.exe', 'c:\\program files\\palo alto networks\\globalprotect\\pangphip.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('U',
                                                                                                                                      'GlobalProtect '
                                                                                                                                      'HIP->cmd: '
                                                                                                                                      'ймовірно '
                                                                                                                                      'HIP-перевірка, '
                                                                                                                                      'не '
                                                                                                                                      'підтверджено'),
 ('pangphipmp.exe', 'c:\\program files\\palo alto networks\\globalprotect\\pangphipmp.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                             'known app, target not '
                                                                                                                             'resolved (typical of '
                                                                                                                             'benign self/child '
                                                                                                                             'threads)'),
 ('pangps.exe', 'c:\\program files\\palo alto networks\\globalprotect\\pangps.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('U', 'pangps->cmd'),
 ('pcaui.exe', 'c:\\windows\\system#\\pcaui.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                   'known app, target not resolved (typical of benign self/child '
                                                                                   'threads)'),
 ('pcvisit_service_client.exe', 'c:\\users\\<u>\\appdata\\local\\pcvisit software ag\\caloa\\pcvisit.support.guest\\release\\#.#.#.#\\pcvisit_service_client.exe', '&lt;unknown process&gt;', ''): ('U',
                                                                                                                                                                                                    'pcvisit '
                                                                                                                                                                                                    'support '
                                                                                                                                                                                                    'guest'),
 ('pintaskbar.exe', 'c:\\users\\<u>\\appdata\\local\\kingsoft\\wps office\\#.#.#.#\\office#\\pintaskbar.exe', 'c:\\windows\\explorer.exe', 'explorer.exe'): ('B',
                                                                                                                                                             'WPS '
                                                                                                                                                             'pintaskbar '
                                                                                                                                                             '-> '
                                                                                                                                                             'explorer.exe: '
                                                                                                                                                             'shell '
                                                                                                                                                             'integration, '
                                                                                                                                                             'known '
                                                                                                                                                             'WPS '
                                                                                                                                                             'behavior'),
 ('powerpnt.exe', 'c:\\program files\\microsoft office\\office#\\powerpnt.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                 'known app, target not resolved '
                                                                                                                 '(typical of benign self/child '
                                                                                                                 'threads)'),
 ('powerpnt.exe', 'c:\\program files\\microsoft office\\root\\office#\\powerpnt.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                       'known app, target not '
                                                                                                                       'resolved (typical of benign '
                                                                                                                       'self/child threads)'),
 ('powerpnt.exe', 'c:\\progra~#\\micros~#\\office#\\powerpnt.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                    'known app, target not resolved (typical of '
                                                                                                    'benign self/child threads)'),
 ('powershell.exe', 'c:\\windows\\system#\\windowspowershell\\v#.#\\powershell.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\python\\launcher\\py.exe', 'py.exe'): ('U',
                                                                                                                                                                       'powershell->py.exe'),
 ('powertoys.exe', 'c:\\users\\<u>\\appdata\\local\\powertoys\\powertoys.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                'known app, target not resolved '
                                                                                                                '(typical of benign self/child '
                                                                                                                'threads)'),
 ('prevhost.exe', 'c:\\windows\\system#\\prevhost.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                         'known app, target not resolved (typical of benign '
                                                                                         'self/child threads)'),
 ('prevhost.exe', 'c:\\windows\\syswow#\\prevhost.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                         'known app, target not resolved (typical of benign '
                                                                                         'self/child threads)'),
 ('primapower.connect.client.exe', 'c:\\program files (x#)\\prima power connect\\primapower.connect.client.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                  'known '
                                                                                                                                                  'app, '
                                                                                                                                                  'target '
                                                                                                                                                  'not '
                                                                                                                                                  'resolved '
                                                                                                                                                  '(typical '
                                                                                                                                                  'of '
                                                                                                                                                  'benign '
                                                                                                                                                  'self/child '
                                                                                                                                                  'threads)'),
 ('psexpressbroker.exe', 'c:\\program files\\windowsapps\\adobesystemsincorporated.adobephotoshopexpress_#.#.#.#_x#__mtcwf#zmmt#c\\psexpressbroker.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                          'known '
                                                                                                                                                                                          'app, '
                                                                                                                                                                                          'target '
                                                                                                                                                                                          'not '
                                                                                                                                                                                          'resolved '
                                                                                                                                                                                          '(typical '
                                                                                                                                                                                          'of '
                                                                                                                                                                                          'benign '
                                                                                                                                                                                          'self/child '
                                                                                                                                                                                          'threads)'),
 ('psexpressbroker.exe', 'c:\\program files\\windowsapps\\adobesystemsincorporated.adobephotoshopexpress_#.#.#.#_x#__mtcwf#zmmt#c\\psexpressbroker.exe', 'c:\\windows\\system#\\windowspowershell\\v#.#\\powershell.exe', 'powershell.exe'): ('U',
                                                                                                                                                                                                                                              'OEM/vendor '
                                                                                                                                                                                                                                              'service '
                                                                                                                                                                                                                                              '-> '
                                                                                                                                                                                                                                              'shell '
                                                                                                                                                                                                                                              '(command '
                                                                                                                                                                                                                                              'line '
                                                                                                                                                                                                                                              'unseen)'),
 ('py-manager.exe', 'c:\\program files\\windowsapps\\pythonsoftwarefoundation.pythonmanager_#.#.#.#_x#__#v#x#pw#km\\py-manager.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                      'known '
                                                                                                                                                                      'app, '
                                                                                                                                                                      'target '
                                                                                                                                                                      'not '
                                                                                                                                                                      'resolved '
                                                                                                                                                                      '(typical '
                                                                                                                                                                      'of '
                                                                                                                                                                      'benign '
                                                                                                                                                                      'self/child '
                                                                                                                                                                      'threads)'),
 ('py.exe', 'c:\\program files\\windowsapps\\pythonsoftwarefoundation.pythonmanager_#.#.#.#_x#__#v#x#pw#km\\py.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                      'known '
                                                                                                                                                      'app, '
                                                                                                                                                      'target '
                                                                                                                                                      'not '
                                                                                                                                                      'resolved '
                                                                                                                                                      '(typical '
                                                                                                                                                      'of '
                                                                                                                                                      'benign '
                                                                                                                                                      'self/child '
                                                                                                                                                      'threads)'),
 ('python.exe', 'c:\\program files\\windowsapps\\pythonsoftwarefoundation.pythonmanager_#.#.#.#_x#__#v#x#pw#km\\python.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                              'known '
                                                                                                                                                              'app, '
                                                                                                                                                              'target '
                                                                                                                                                              'not '
                                                                                                                                                              'resolved '
                                                                                                                                                              '(typical '
                                                                                                                                                              'of '
                                                                                                                                                              'benign '
                                                                                                                                                              'self/child '
                                                                                                                                                              'threads)'),
 ('python.exe', 'd:\\project\\msp\\venv\\scripts\\python.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                'known app, target not resolved (typical of benign '
                                                                                                'self/child threads)'),
 ('qasvc.exe', 'c:\\program files\\acer\\quick access service\\qasvc.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                            'known app, target not resolved (typical '
                                                                                                            'of benign self/child threads)'),
 ('radeonsoftware.exe', 'c:\\program files\\windowsapps\\advancedmicrodevicesinc-#.amdradeonsoftware_#.#.#.#_x#__#a#xs#nr#m\\radeonsoftware\\radeonsoftware.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                                                   'known '
                                                                                                                                                                                                   'app, '
                                                                                                                                                                                                   'target '
                                                                                                                                                                                                   'not '
                                                                                                                                                                                                   'resolved '
                                                                                                                                                                                                   '(typical '
                                                                                                                                                                                                   'of '
                                                                                                                                                                                                   'benign '
                                                                                                                                                                                                   'self/child '
                                                                                                                                                                                                   'threads)'),
 ('rdpclip.exe', 'c:\\windows\\system#\\rdpclip.exe', '<unknown process>', ''): ('B',
                                                                                 'known app, target not resolved (typical of benign self/child '
                                                                                 'threads)'),
 ('reader_sl.exe', 'c:\\program files (x#)\\adobe\\acrobat reader dc\\reader\\reader_sl.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                               'known app, target '
                                                                                                                               'not resolved '
                                                                                                                               '(typical of benign '
                                                                                                                               'self/child threads)'),
 ('regsvr#.exe', 'c:\\windows\\system#\\regsvr#.exe', '&lt;unknown process&gt;', ''): ('U', 'regsvr32 як інжектор'),
 ('rphost.exe', 'c:\\program files\\#cv#\\#.#.#.#\\bin\\rphost.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                      'known app, target not resolved (typical of '
                                                                                                      'benign self/child threads)'),
 ('rtkauduservice#.exe', 'c:\\windows\\system#\\driverstore\\filerepository\\realtekservice.inf_amd#_ac#e#c#c#c#\\rtkauduservice#.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                         'known '
                                                                                                                                                                         'app, '
                                                                                                                                                                         'target '
                                                                                                                                                                         'not '
                                                                                                                                                                         'resolved '
                                                                                                                                                                         '(typical '
                                                                                                                                                                         'of '
                                                                                                                                                                         'benign '
                                                                                                                                                                         'self/child '
                                                                                                                                                                         'threads)'),
 ('rtkauduservice#.exe', 'c:\\windows\\system#\\driverstore\\filerepository\\realtekservice.inf_amd#_ac#e#c#c#c#\\rtkauduservice#.exe', 'c:\\windows\\system#\\windowspowershell\\v#.#\\powershell.exe', 'powershell.exe'): ('U',
                                                                                                                                                                                                                             'OEM/vendor '
                                                                                                                                                                                                                             'service '
                                                                                                                                                                                                                             '-> '
                                                                                                                                                                                                                             'shell '
                                                                                                                                                                                                                             '(command '
                                                                                                                                                                                                                             'line '
                                                                                                                                                                                                                             'unseen)'),
 ('rtkauduservice#.exe', 'c:\\windows\\system#\\driverstore\\filerepository\\realtekservice.inf_amd#_ef#a#e#c#\\rtkauduservice#.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                       'known '
                                                                                                                                                                       'app, '
                                                                                                                                                                       'target '
                                                                                                                                                                       'not '
                                                                                                                                                                       'resolved '
                                                                                                                                                                       '(typical '
                                                                                                                                                                       'of '
                                                                                                                                                                       'benign '
                                                                                                                                                                       'self/child '
                                                                                                                                                                       'threads)'),
 ('rtkauduservice#.exe', 'c:\\windows\\system#\\driverstore\\filerepository\\realtekservice.inf_amd#_f#c#e#b#\\rtkauduservice#.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                      'known '
                                                                                                                                                                      'app, '
                                                                                                                                                                      'target '
                                                                                                                                                                      'not '
                                                                                                                                                                      'resolved '
                                                                                                                                                                      '(typical '
                                                                                                                                                                      'of '
                                                                                                                                                                      'benign '
                                                                                                                                                                      'self/child '
                                                                                                                                                                      'threads)'),
 ('rtkauduservice#.exe', 'c:\\windows\\system#\\driverstore\\filerepository\\realtekservice.inf_amd#_f#c#e#b#\\rtkauduservice#.exe', 'c:\\windows\\system#\\windowspowershell\\v#.#\\powershell.exe', 'powershell.exe'): ('U',
                                                                                                                                                                                                                          'OEM/vendor '
                                                                                                                                                                                                                          'service '
                                                                                                                                                                                                                          '-> '
                                                                                                                                                                                                                          'shell '
                                                                                                                                                                                                                          '(command '
                                                                                                                                                                                                                          'line '
                                                                                                                                                                                                                          'unseen)'),
 ('runonce.exe', 'c:\\windows\\system#\\runonce.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                       'known app, target not resolved (typical of benign self/child '
                                                                                       'threads)'),
 ('runtimebroker.exe', 'c:\\windows\\system#\\runtimebroker.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                   'known app, target not resolved (typical of '
                                                                                                   'benign self/child threads)'),
 ('rustdesk.exe', 'c:\\program files\\rustdesk\\rustdesk.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('U',
                                                                                                             'RustDesk->cmd (авторизований, але '
                                                                                                             'cmd)'),
 ('scalc.exe', 'c:\\program files\\libreoffice\\program\\scalc.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                      'known app, target not resolved (typical of '
                                                                                                      'benign self/child threads)'),
 ('setup.exe', 'c:\\program files (x#)\\microsoft\\edge\\application\\#.#.#.#\\installer\\setup.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                       'known app, '
                                                                                                                                       'target not '
                                                                                                                                       'resolved '
                                                                                                                                       '(typical of '
                                                                                                                                       'benign '
                                                                                                                                       'self/child '
                                                                                                                                       'threads)'),
 ('setup.exe', 'c:\\windows\\system#\\driverstore\\filerepository\\nvhm.inf_amd#_fc#fff#a#\\setup.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                         'known app, '
                                                                                                                                         'target not '
                                                                                                                                         'resolved '
                                                                                                                                         '(typical '
                                                                                                                                         'of benign '
                                                                                                                                         'self/child '
                                                                                                                                         'threads)'),
 ('sh.exe', 'c:\\program files\\git\\usr\\bin\\sh.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                         'known app, target not resolved (typical of benign '
                                                                                         'self/child threads)'),
 ('sh.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\git\\usr\\bin\\sh.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                'known app, target not resolved '
                                                                                                                '(typical of benign self/child '
                                                                                                                'threads)'),
 ('simpress.exe', 'c:\\program files\\libreoffice\\program\\simpress.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                            'known app, target not resolved (typical '
                                                                                                            'of benign self/child threads)'),
 ('skype.exe', 'c:\\program files (x#)\\microsoft\\skype for desktop\\skype.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                   'known app, target not resolved '
                                                                                                                   '(typical of benign self/child '
                                                                                                                   'threads)'),
 ('sldworks.exe', 'c:\\program files\\solidworks corp\\solidworks\\sldworks.exe', 'c:\\windows\\system#\\rundll#.exe', 'rundll#.exe'): ('B',
                                                                                                                                        'cross-process '
                                                                                                                                        'thread '
                                                                                                                                        'between '
                                                                                                                                        'known '
                                                                                                                                        'system/app '
                                                                                                                                        'binaries '
                                                                                                                                        '(sldworks.exe->rundll#.exe)'),
 ('soffice.bin', 'c:\\program files\\libreoffice\\program\\soffice.bin', '&lt;unknown process&gt;', ''): ('B',
                                                                                                          'known app, target not resolved (typical '
                                                                                                          'of benign self/child threads)'),
 ('spoolsv.exe', 'c:\\windows\\system#\\spoolsv.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                       'known app, target not resolved (typical of benign self/child '
                                                                                       'threads)'),
 ('sqlagent.exe', 'c:\\program files\\microsoft sql server\\mssql#.mssqlserver\\mssql\\binn\\sqlagent.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                             'known '
                                                                                                                                             'app, '
                                                                                                                                             'target '
                                                                                                                                             'not '
                                                                                                                                             'resolved '
                                                                                                                                             '(typical '
                                                                                                                                             'of '
                                                                                                                                             'benign '
                                                                                                                                             'self/child '
                                                                                                                                             'threads)'),
 ('ssdal.exe', 'c:\\windows\\ssdal.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                          'known app, target not resolved (typical of benign self/child threads)'),
 ('sshd.exe', 'c:\\windows\\system#\\openssh\\sshd.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                          'known app, target not resolved (typical of benign '
                                                                                          'self/child threads)'),
 ('sursvc.exe', 'c:\\program files\\intel\\sur\\queencreek\\sursvc.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                          'known app, target not resolved (typical '
                                                                                                          'of benign self/child threads)'),
 ('swriter.exe', 'c:\\program files\\libreoffice\\program\\swriter.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                          'known app, target not resolved (typical '
                                                                                                          'of benign self/child threads)'),
 ('t#.exe', 'c:\\trumpf.net\\applications\\tops#\\bin\\t#.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                 'known app, target not resolved (typical of benign '
                                                                                                 'self/child threads)'),
 ('tcad.exe', 'c:\\trumpf.net\\applications\\topscad\\bin\\tcad.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                       'known app, target not resolved (typical of '
                                                                                                       'benign self/child threads)'),
 ('telegram.exe', 'c:\\program files\\windowsapps\\telegrammessengerllp.telegramdesktop_#.#.#.#_x#__t#vj#pshhgkwm\\telegram.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                   'known '
                                                                                                                                                                   'app, '
                                                                                                                                                                   'target '
                                                                                                                                                                   'not '
                                                                                                                                                                   'resolved '
                                                                                                                                                                   '(typical '
                                                                                                                                                                   'of '
                                                                                                                                                                   'benign '
                                                                                                                                                                   'self/child '
                                                                                                                                                                   'threads)'),
 ('telegram.exe', 'c:\\users\\<u>\\appdata\\roaming\\telegram desktop\\telegram.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                       'known app, target not '
                                                                                                                       'resolved (typical of benign '
                                                                                                                       'self/child threads)'),
 ('telegram.exe', 'c:\\users\\<u>\\desktop\\telegram desktop\\telegram.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                              'known app, target not resolved '
                                                                                                              '(typical of benign self/child '
                                                                                                              'threads)'),
 ('telegram.exe', 'c:\\users\\<u>\\desktop\\telegram.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                            'known app, target not resolved (typical of benign '
                                                                                            'self/child threads)'),
 ('telegram.exe', 'd:\\telegram desktop\\telegram desktop\\telegram.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                           'known app, target not resolved (typical '
                                                                                                           'of benign self/child threads)'),
 ('telegram.exe', 'd:\\telegram desktop\\telegram.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                         'known app, target not resolved (typical of benign '
                                                                                         'self/child threads)'),
 ('telegram.exe', 'd:\\telegram\\telegram desktop\\telegram.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                   'known app, target not resolved (typical of '
                                                                                                   'benign self/child threads)'),
 ('telegram.exe', 'd:\\users\\<u>\\appdata\\roaming\\telegram desktop\\telegram.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                       'known app, target not '
                                                                                                                       'resolved (typical of benign '
                                                                                                                       'self/child threads)'),
 ('testhost.exe', 'd:\\modern\\solidworks-mcp-unified\\tests\\swmcp.tests\\bin\\release\\net#.#-windows\\testhost.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                         'known '
                                                                                                                                                         'app, '
                                                                                                                                                         'target '
                                                                                                                                                         'not '
                                                                                                                                                         'resolved '
                                                                                                                                                         '(typical '
                                                                                                                                                         'of '
                                                                                                                                                         'benign '
                                                                                                                                                         'self/child '
                                                                                                                                                         'threads)'),
 ('timeout.exe', 'c:\\program files\\git\\usr\\bin\\timeout.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                   'known app, target not resolved (typical of '
                                                                                                   'benign self/child threads)'),
 ('timeout.exe', 'c:\\program files\\git\\usr\\bin\\timeout.exe', 'c:\\users\\<u>\\appdata\\local\\programs\\python\\launcher\\py.exe', 'py.exe'): ('B',
                                                                                                                                                    'cross-process '
                                                                                                                                                    'thread '
                                                                                                                                                    'between '
                                                                                                                                                    'known '
                                                                                                                                                    'system/app '
                                                                                                                                                    'binaries '
                                                                                                                                                    '(timeout.exe->py.exe)'),
 ('timeout.exe', 'c:\\program files\\tools\\git\\usr\\bin\\timeout.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                          'known app, target not resolved (typical '
                                                                                                          'of benign self/child threads)'),
 ('totalcmd#.exe', 'c:\\users\\<u>\\total_prt\\totalcmd#.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                'known app, target not resolved (typical of benign '
                                                                                                'self/child threads)'),
 ('totalcmd#.exe', 'd:\\total commander_#\\totalcmd#.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                            'known app, target not resolved (typical of benign '
                                                                                            'self/child threads)'),
 ('trumpf.trutops.control.shell.exe', 'c:\\program files\\trumpf\\trutops\\client\\control\\trumpf.trutops.control.shell.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                'known '
                                                                                                                                                                'app, '
                                                                                                                                                                'target '
                                                                                                                                                                'not '
                                                                                                                                                                'resolved '
                                                                                                                                                                '(typical '
                                                                                                                                                                'of '
                                                                                                                                                                'benign '
                                                                                                                                                                'self/child '
                                                                                                                                                                'threads)'),
 ('uninstall.exe', 'c:\\users\\<u>\\appdata\\local\\grammarly\\desktopintegrations\\uninstall.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                     'known app, '
                                                                                                                                     'target not '
                                                                                                                                     'resolved '
                                                                                                                                     '(typical of '
                                                                                                                                     'benign '
                                                                                                                                     'self/child '
                                                                                                                                     'threads)'),
 ('updater.exe', 'c:\\program files (x#)\\google\\googleupdater\\#.#.#.#\\updater.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                         'known app, target not '
                                                                                                                         'resolved (typical of '
                                                                                                                         'benign self/child '
                                                                                                                         'threads)'),
 ('updater.exe', 'c:\\program files (x#)\\skillbrains\\updater\\<ip-ext>\\updater.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                         'known app, target not '
                                                                                                                         'resolved (typical of '
                                                                                                                         'benign self/child '
                                                                                                                         'threads)'),
 ('userinit.exe', 'c:\\windows\\system#\\userinit.exe', 'c:\\windows\\explorer.exe', 'explorer.exe'): ('B',
                                                                                                       'cross-process thread between known '
                                                                                                       'system/app binaries '
                                                                                                       '(userinit.exe->explorer.exe)'),
 ('userinit.exe', 'c:\\windows\\system#\\userinit.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('B',
                                                                                                      'managed agent or dev tool starting shell'),
 ('ventoy#disk.exe', 'c:\\users\\<u>\\desktop\\ventoy-#.#.#\\ventoy#disk.exe', '&lt;unknown process&gt;', ''): ('U', 'ventoy з Desktop'),
 ('viber.exe', 'c:\\users\\<u>\\appdata\\local\\viber\\viber.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                    'known app, target not resolved (typical of '
                                                                                                    'benign self/child threads)'),
 ('vibersetup.exe', 'c:\\users\\<u>\\downloads\\vibersetup.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                  'known app, target not resolved (typical of benign '
                                                                                                  'self/child threads)'),
 ('vscodeusersetup-x#-#.#.#.tmp', 'c:\\users\\<u>\\appdata\\local\\temp\\is-knk#.tmp\\vscodeusersetup-x#-#.#.#.tmp', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                      'known '
                                                                                                                                                      'app, '
                                                                                                                                                      'target '
                                                                                                                                                      'not '
                                                                                                                                                      'resolved '
                                                                                                                                                      '(typical '
                                                                                                                                                      'of '
                                                                                                                                                      'benign '
                                                                                                                                                      'self/child '
                                                                                                                                                      'threads)'),
 ('webpluginservice.exe', 'c:\\program files (x#)\\web plugins\\webpluginservice.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                        'known app, target not '
                                                                                                                        'resolved (typical of benign '
                                                                                                                        'self/child threads)'),
 ('werfault.exe', 'c:\\windows\\syswow#\\werfault.exe', 'c:\\program files (x#)\\adobe\\acrobat reader dc\\reader\\acrord#.exe', 'acrord#.exe'): ('B',
                                                                                                                                                  'cross-process '
                                                                                                                                                  'thread '
                                                                                                                                                  'between '
                                                                                                                                                  'known '
                                                                                                                                                  'system/app '
                                                                                                                                                  'binaries '
                                                                                                                                                  '(werfault.exe->acrord#.exe)'),
 ('wermgr.exe', 'c:\\windows\\system#\\wermgr.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                     'known app, target not resolved (typical of benign self/child '
                                                                                     'threads)'),
 ('wermgr.exe', 'c:\\windows\\system#\\wermgr.exe', 'c:\\windows\\system#\\rundll#.exe', 'rundll#.exe'): ('B',
                                                                                                          'cross-process thread between known '
                                                                                                          'system/app binaries '
                                                                                                          '(wermgr.exe->rundll#.exe)'),
 ('windowsterminal.exe', 'c:\\program files\\windowsapps\\microsoft.windowsterminal_#.#.#.#_x#__#wekyb#d#bbwe\\windowsterminal.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                                      'known '
                                                                                                                                                                      'app, '
                                                                                                                                                                      'target '
                                                                                                                                                                      'not '
                                                                                                                                                                      'resolved '
                                                                                                                                                                      '(typical '
                                                                                                                                                                      'of '
                                                                                                                                                                      'benign '
                                                                                                                                                                      'self/child '
                                                                                                                                                                      'threads)'),
 ('winword.exe', 'c:\\program files (x#)\\microsoft office\\office#\\winword.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                    'known app, target not resolved '
                                                                                                                    '(typical of benign self/child '
                                                                                                                    'threads)'),
 ('winword.exe', 'c:\\program files\\microsoft office\\office#\\winword.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                               'known app, target not resolved '
                                                                                                               '(typical of benign self/child '
                                                                                                               'threads)'),
 ('winword.exe', 'c:\\program files\\microsoft office\\office#\\winword.exe', 'c:\\program files\\microsoft office\\office#\\winword.exe', 'winword.exe'): ('B',
                                                                                                                                                            'self-injection '
                                                                                                                                                            'into '
                                                                                                                                                            'same '
                                                                                                                                                            'binary '
                                                                                                                                                            '(app '
                                                                                                                                                            'updater/sandbox)'),
 ('winword.exe', 'c:\\program files\\microsoft office\\root\\office#\\winword.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                     'known app, target not resolved '
                                                                                                                     '(typical of benign self/child '
                                                                                                                     'threads)'),
 ('winword.exe', 'c:\\progra~#\\micros~#\\office#\\winword.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                  'known app, target not resolved (typical of benign '
                                                                                                  'self/child threads)'),
 ('wordpad.exe', 'c:\\program files\\windows nt\\accessories\\wordpad.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                             'known app, target not resolved '
                                                                                                             '(typical of benign self/child '
                                                                                                             'threads)'),
 ('wps.exe', 'c:\\users\\<u>\\appdata\\local\\kingsoft\\wps office\\#.#.#.#\\office#\\wps.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                 'known app, target '
                                                                                                                                 'not resolved '
                                                                                                                                 '(typical of benign '
                                                                                                                                 'self/child '
                                                                                                                                 'threads)'),
 ('wpscenter.exe', 'c:\\users\\<u>\\appdata\\local\\kingsoft\\wps office\\#.#.#.#\\office#\\wpscenter.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                             'known '
                                                                                                                                             'app, '
                                                                                                                                             'target '
                                                                                                                                             'not '
                                                                                                                                             'resolved '
                                                                                                                                             '(typical '
                                                                                                                                             'of '
                                                                                                                                             'benign '
                                                                                                                                             'self/child '
                                                                                                                                             'threads)'),
 ('wpscloudsvr.exe', 'c:\\program files\\kingsoft\\office#\\wpscloudsvr.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                               'known app, target not resolved '
                                                                                                               '(typical of benign self/child '
                                                                                                               'threads)'),
 ('wpscloudsvr.exe', 'c:\\users\\<u>\\appdata\\local\\kingsoft\\wps office\\#.#.#.#\\office#\\wpscloudsvr.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                                 'known '
                                                                                                                                                 'app, '
                                                                                                                                                 'target '
                                                                                                                                                 'not '
                                                                                                                                                 'resolved '
                                                                                                                                                 '(typical '
                                                                                                                                                 'of '
                                                                                                                                                 'benign '
                                                                                                                                                 'self/child '
                                                                                                                                                 'threads)'),
 ('wpspdf.exe', 'c:\\users\\<u>\\appdata\\local\\kingsoft\\wps office\\#.#.#.#\\office#\\wpspdf.exe', '&lt;unknown process&gt;', ''): ('B',
                                                                                                                                       'known app, '
                                                                                                                                       'target not '
                                                                                                                                       'resolved '
                                                                                                                                       '(typical of '
                                                                                                                                       'benign '
                                                                                                                                       'self/child '
                                                                                                                                       'threads)'),
 ('wscript.exe', 'c:\\windows\\system#\\wscript.exe', '&lt;unknown process&gt;', ''): ('S', 'wscript->unknown'),
 ('wscript.exe', 'c:\\windows\\system#\\wscript.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('S',
                                                                                                    'wscript->cmd.exe: скриптовий хост запускає cmd'),
 ('ww#.exe', 'c:\\ww#\\ww#.exe', '&lt;unknown process&gt;', ''): ('U', 'ww#.exe невідоме ПЗ'),
 ('zabbix_agentd.exe', 'c:\\program files\\zabbix agent\\zabbix_agentd.exe', 'c:\\windows\\system#\\cmd.exe', 'cmd.exe'): ('B',
                                                                                                                           'managed agent or dev '
                                                                                                                           'tool starting shell')}

RANK={'N':0,'B':1,'U':2,'S':3}
def lo(e): return {k.lower():v for k,v in e.items()}
def f(v):
    try: return float(v)
    except: return 0.0
def isint(ip): return str(ip).startswith(('10.','192.168.','172.16.','172.17.','172.18.','172.19.','172.2','172.3'))
BEN_CAT=('google','windows update','appgroup','low-risk','computer-and-internet','content-delivery','business','reference','online-storage','streaming','social','artificial','internet-comm','shopping','messang','web-hosting','personal','shareware','web-adv','news','travel','education','search','software','financial','health','government','entertainment','sports','job','real-estate')
BAD_CAT=('malware','command-and-control','phishing','proxy-avoidance','hacking','grayware','ransomware','parked','high-risk','dynamic-dns','questionable')
def row_label(e,lens):
    d=lo(e); k=set(d)
    if 'injector_path' in k or 'injector' in k:
        key=tuple(norm_value(d.get(x,'')) if x in d else '?' for x in ('injector','injector_path','target_path'))+(norm_value(d['target_proc']) if 'target_proc' in d else '',)
        key=(key[0] if key[0]!='' else '?',)+key[1:]
        if key in LK: return tuple(LK[key])
        # fallback: ignore target_proc
        for kk,v in LK.items():
            if kk[:3]==key[:3]: return tuple(v)
        return ('U','injector row not in reviewed table')
    if 'beacon_count' in k:
        app=str(d.get('app','')); cat=str(d.get('category','')).lower()
        if any(b in cat for b in BAD_CAT): return ('S','beacon category '+cat)
        if app in('incomplete','insufficient-data','unknown-tcp','unknown-udp','unknown-p2p','not-applicable') or cat in('insufficient-content',): return ('U','beacon to unclassified app (%s)'%app)
        if cat=='remote-access' and app!='chrome-remote-desktop': return ('U','remote-access beacon (%s)'%app)
        return ('B','beacon of recognized app/category (%s/%s); destination not in signature'%(app,cat))
    if 'conns' in k:  # outbound summary rows
        app=str(d.get('app','')); cat=str(d.get('category','')).lower()
        if any(b in cat for b in BAD_CAT): return ('S','outbound category '+cat)
        if app in('incomplete','insufficient-data','unknown-tcp','unknown-udp','unknown-p2p'): return ('U','outbound unclassified app')
        return ('B','outbound recognized app/category')
    if 'failed_attempts' in k:
        ev=str(d.get('event_name','')).lower(); fa=f(d['failed_attempts'])
        if 'followed by success' in ev: return ('U','login failures then success for a named account (typical typo or cached creds; not proof of compromise)')
        if 'successful' in ev or 'access accept' in ev or 'validated the credentials' in ev: return ('N','auth success context')
        if not isint(d.get('source_ip','')) and False: return ('B','')
        if fa>=100 and f(d.get('unique_source_ips'))>=5: return ('U','distributed failures (%d from %d sources), no success in row'%(fa,f(d.get('unique_source_ips'))))
        return ('B','failed auth without success')
    if 'event_count' in k and 'event_name' in k:
        ev=str(d['event_name']).lower(); n=f(d['event_count'])
        if any(x in ev for x in('mimikatz','ransom','cobalt','ioc','turla','c2','malware')): return ('S','event name '+ev[:40])
        return ('B','repetitive network/audit event')
    if 'unique_targets' in k:
        ut=f(d['unique_targets']); up=f(d['unique_ports']); sip=str(d.get('src_ip','')); dip=str(d.get('dst_ip',''))
        ev=str(d.get('event','')).lower()
        if isint(sip) and isint(dip) and (ut>=10 or up>=20): return ('S','internal host sweeping/scanning internal targets (%d targets, %d ports)'%(ut,up))
        if isint(sip) and (ut>=50 or up>=100): return ('U','internal host fan-out to many external targets/ports (%d/%d)'%(ut,up))
        return ('B','few targets/ports; deny/traffic context')
    if 'activity' in k:
        a=str(d['activity']).lower(); proc=str(d.get('proc','')).lower()
        if 'turla' in a or 'ioc' in a: return ('S','IOC detection '+a[:40])
        if 'ransomware' in a: return ('U','mailto ransomware heuristic (known noisy)')
        if a.startswith('registryevent') or 'creation time' in a or 'windows update' in a or 'boot menu' in a or 'secure boot' in a or 'time service' in a or 'root certificate' in a or 'database engine' in a: return ('B','routine host activity')
        if 'file decode' in a:
            if proc in('powershell.exe','cmd.exe','mshta.exe','certutil.exe','bitsadmin.exe','wscript.exe','cscript.exe','rundll32.exe','regsvr32.exe'): return ('U','LOLBin '+proc+' in decode chain')
            return ('B','decode chain, proc '+proc[:20])
        if a in('process create','filecreate'):
            pp=str(d.get('proc_path','')).lower()
            if proc in('powershell.exe','cmd.exe','csc.exe','mshta.exe','wscript.exe','cscript.exe'): return ('U',a+' by '+proc+' in decode chain (command line unseen)')
            if any(x in pp for x in('program files','\\windows\\','kingsoft','onedrive','windowsapps','\\hp\\','xerox','chromehost')): return ('B',a+' by installed app '+proc[:24])
            return ('U',a+' by '+proc[:24]+' from non-standard path')
        return ('U','unclassified activity '+a[:30])
    if 'eventname' in k and 'rawpayload' in k:
        en=str(d['eventname']).lower()
        if any(x in en for x in ('mimikatz','ransom','cobalt','turla','ioc')): return ('S','CRE event '+en[:40])
        return ('N','rule-trigger context event')
    return ('U','row shape not covered: '+','.join(sorted(k))[:60])
def label_case(c):
    rows=c['ev']
    if not rows: return None
    worst=('N','');cnt=collections.Counter();why={}
    for e in rows:
        l,r=row_label(e,c['lens']); cnt[l]+=1
        if RANK[l]>RANK[worst[0]] or (l==worst[0] and l in('S','U') and not worst[1]): worst=(l,r)
    return worst,dict(cnt)


def events_of(prompt):
    i = prompt.find("[{"); j = prompt.find("--- END OF LOGS ---")
    if i < 0 or j < 0:
        return None
    seg = prompt[i:j].strip()
    for _ in range(60):
        try:
            return ast.literal_eval(seg)
        except Exception:
            k = seg.rfind("}, {")
            if k < 0:
                return None
            seg = seg[:k + 1] + "]"
    return None


def main(db, out):
    c = sqlite3.connect(db)
    res = []
    for u, lens, pz in c.execute("select ukey,lens,example_prompt_z from ai_unique where source='qradar' and claude_label is null"):
        ev = events_of(zlib.decompress(pz).decode())
        r = label_case({"ev": ev, "lens": lens})
        if r is None:
            continue
        (w, reason), cnt = r
        lab, cl, txt = {"S": ("review", "suspicious", "HYPOTHESIS: " + reason), "U": ("close", "insufficient_data", reason),
                        "B": ("close", "benign", reason)}.get(w, ("close", "insufficient_data", "evidence rows are only rule-trigger events; actual chain details not in saved evidence"))
        res.append([u, lab + "|" + cl, "rows %s; %s" % (dict(cnt), txt)])
    json.dump(res, open(out, "w"), ensure_ascii=False)
    print(len(res), collections.Counter(x[1] for x in res))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
