from toolbox.PKSig import PKSig
from toolbox.pairinggroup import *
from charm.engine.util import *
import sys, random, string
from toolbox.pairinggroup import PairingGroup,G1,G2,ZR,pair
import sys
from toolbox.pairinggroup import *
from ver_hess import verifySigsRecursive

group = None
debug = None
H1 = None
H2 = None
bodyKey = 'Body'

def prng_bits(bits=80):
	return group.init(ZR, randomBits(bits))

def __init__( groupObj ) : 
	global group , debug 
	group= groupObj 
	debug= False 

def run_Batch(verifyArgsDict, groupObjParam, verifyFuncArgs):
	global group
	global debug, H1, H2
	group = groupObjParam

	N = len(verifyArgsDict)
	z = 0
	delta = {}
	for z in range(0, N):
		delta[z] = prng_bits(80)

	incorrectIndices = []
	H2 = lambda x,y: group.hash((x,y), ZR)
	H1 = lambda x: group.hash(x, G1)
	__init__(group)


	for z in range(0, N):
		#for arg in verifyFuncArgs:
			#if (group.ismember(verifyArgsDict[z][arg][bodyKey]) == False):
				#sys.exit("ALERT:  Group membership check failed!!!!\n")

		pass

	z = 0
	startSigNum = 0
	endSigNum = N

	dotA = {}
	dotB = {}
	dotC = {}

	for z in range(0, N):
		S1= verifyArgsDict[z]['sig'][bodyKey][ 'S1' ]
		S2= verifyArgsDict[z]['sig'][bodyKey][ 'S2' ]
		a= H2( verifyArgsDict[z]['M'][bodyKey] , S1 )

		dotA[z] =   S2 ** delta [ z ]  
		dotB[z] =   verifyArgsDict[z]['pk'][bodyKey] **( a * delta [ z ] )  
		dotC[z] =   S1 ** delta [ z ]  

	verifySigsRecursive(verifyArgsDict, group, incorrectIndices, 0, N, delta, dotA, dotB, dotC)

	return incorrectIndices
