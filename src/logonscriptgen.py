#!/usr/bin/python
# -*- encoding: UTF-8 -*-
#------------------------------------------------------------------------------
"""
Simple login script generator
"""
#------------------------------------------------------------------------------
import optparse as op
import logging as log
import os.path
import xml.sax as xs
import re
from string import Template
#------------------------------------------------------------------------------
class RulesFileHandler(xs.ContentHandler):
    #--------------------------------------------------------------------------
    def __init__(self, outPutFile, params):
        xs.ContentHandler.__init__(self)
        
        self.out = outPutFile
        self.params = params
        
        self.currTxt = ''
        self.currAttrs = None
        self.addCurTxt = False
    #--------------------------------------------------------------------------
    def startElement(self, name, attrs):
        if name == 'rule':
            if len(attrs) == 0:
                log.debug('Rule with no matchers. Adding text')
                self.addCurTxt = True
            else:
                for attr in attrs.keys():
                    if attr == 'matchIP':
                        val = attrs[attr]
                        log.debug('IP matching rule (%s).', val)
                        if re.match(val, self.params['clientIP']):
                            log.debug('IP rule matched to: %s. Adding text.', self.params['clientIP'])
                            self.addCurTxt = True
                    elif attr == 'matchGroup':
                        val = attrs[attr]
                        log.debug('Group matching rule (%s).', val)
                        if re.match(val, self.params['group']):
                            log.debug('Group rule matched to: %s. Adding text.', self.params['group'])
                            self.addCurTxt = True
                    elif attr == 'matchUser':
                        val = attrs[attr]
                        log.debug('User matching rule (%s).', val)
                        if re.match(val, self.params['user']):
                            log.debug('User rule matched to: %s. Adding text.', self.params['user'])
                            self.addCurTxt = True
                    else:
                        log.debug('Unknown attribute. Not adding rule.')
    #--------------------------------------------------------------------------
    def characters(self, ch):
        self.currTxt += ch
    #--------------------------------------------------------------------------
    def endElement(self, name):
        if name == 'rule':
            
            if self.addCurTxt and self.currTxt:
                for line in self.currTxt.split('\n'):
                    line = line.strip()
                    if line:
                        line = Template(line).substitute(self.params)
                        log.debug('There is a text to be added: %s', line)
                        self.out.write(line + '\r\n')
                
        self.addCurTxt = False
        self.currTxt = ''
#------------------------------------------------------------------------------
class LogonScriptGen(object):
    #--------------------------------------------------------------------------
    def __init__(self, 
                 rulesFileName = '/etc/logonscriptrules.conf',
                 outputDir = '/var/shares/netlogon',
                 outputFileTmpl = '$user$clientIP.bat'):
    
        self.outputDir = outputDir
        self.outPutFileTempl = Template(outputFileTmpl)
        self.rulesFileName = rulesFileName
    #--------------------------------------------------------------------------
    def generate(self, **params):
        log.debug('Parameters given to generate: %s', params)
        
        fileName = self.outPutFileTempl.safe_substitute(params)
        fileName = os.path.join(params['outputDir'], fileName)
        
        log.debug('Opening script file (%s)', fileName)
        scrFile = open(fileName, 'wb')
        
        ch = RulesFileHandler(scrFile, params)
        sxp = xs.make_parser()
        
        sxp.setContentHandler(ch)
        sxp.parse('file:%s' % self.rulesFileName)
        
        scrFile.close()
#------------------------------------------------------------------------------
def main():
    parser = op.OptionParser(usage = 'Usage: %prog [options]')
    
    parser.add_option('-r',
                      '--rulesFileName',
                      type = 'string',
                      dest = 'rulesFileName',
                      default = '/etc/logonscriptrules.conf',
                      help = 'Name of file with rules')
                      
    parser.add_option('-d',
                      '--outputDir',
                      type = 'string',
                      dest = 'outputDir',
                      default = '/var/shares/netlogon',
                      help = 'Directory to where the files will be outputted')
    
    parser.add_option('-t',
                      '--outputFileTmpl',
                      type = 'string',
                      dest = 'outputFileTmpl',
                      default = '$user$clientIP.bat',
                      help = 'Output filename template')
    
    parser.add_option('-u',
                      '--user',
                      type = 'string',
                      dest = 'user',
                      default = '',
                      help = 'Intended username')
                      
    parser.add_option('-g',
                      '--group',
                      type = 'string',
                      dest = 'group',
                      default = '',
                      help = 'Primary group of intended user')
    
    parser.add_option('--clientName',
                      type = 'string',
                      dest = 'clientName',
                      default = '',
                      help = 'DNS name of connected client')
                      
    parser.add_option('--clientIP',
                      type = 'string',
                      dest = 'clientIP',
                      default = '',
                      help = 'IP of connected client')
                      
    parser.add_option('--debugLevel',
                      type = 'string',
                      dest = 'debugLevel',
                      default = 'CRITICAL',
                      help = 'Debug level')
                      
    options, args = parser.parse_args()
    
    debugLevel = getattr(log, options.debugLevel, log.CRITICAL)
    
    log.basicConfig(level = debugLevel,
                    format = '%(asctime)s %(levelname)-8s %(message)s')
    
    lg = LogonScriptGen(options.rulesFileName,
                        options.outputDir,
                        options.outputFileTmpl)
                        
    lg.generate(**options.__dict__)
#------------------------------------------------------------------------------
if __name__ == '__main__':
    main()