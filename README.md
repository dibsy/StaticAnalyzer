# StaticAnalyzer
## StaticAnalyzer is a burp plugin that can be used to perform static analysis during run time active scan. It will search for specific words in the response that is mentioned in the vectors.txt



How to use?

1. Download the StaticAnalyzer.jar file or build the Jar file from the source code by importing the project in eclipse
2. Create a file called vectors.txt in the same location where the BurpSuite executable jar is located and add some vectors
[![Static Analyzer](https://github.com/dibsy/StaticAnalyzer/blob/master/vectors.PNG)]
3. Now start burpsuite
4. Go to the extender tab
5. Click Add and Select the StaticAnalyzer.jar file

Test site : http://housing-agent-pitch-68636.bitballoon.com/

6. Right click on any target and click actively scan this host

[![Static Analyzer](https://github.com/dibsy/StaticAnalyzer/blob/master/issues0.PNG)]

Now you can see in the body the word "git" is highlighted

[![Static Analyzer](https://github.com/dibsy/StaticAnalyzer/blob/master/issues.PNG)]
