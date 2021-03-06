/* AlgorithmParameterGeneratorSpi.java --- Algorithm Parameter Generator SPI
   Copyright (C) 1999 Free Software Foundation, Inc.

This file is part of GNU Classpath.

GNU Classpath is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

GNU Classpath is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Classpath; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301 USA.

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version. */

package java.security;
import java.security.spec.AlgorithmParameterSpec;

/**
   AlgorithmParameterGeneratorSpi is the Service Provider
   Interface for the AlgorithmParameterGenerator class.
   This class is used to generate the algorithm parameters
   for a specific algorithm.

   @since JDK 1.2
   @author Mark Benvenuto
 */
public abstract class AlgorithmParameterGeneratorSpi
{

  /**
     Constructs a new AlgorithmParameterGeneratorSpi
   */
  public AlgorithmParameterGeneratorSpi()
  {
  }

  /**
     Initializes the parameter generator with the specified size
     and SecureRandom

     @param size the size( in number of bits)
     @param random the SecureRandom class to use for randomness
   */
  protected abstract void engineInit(int size, SecureRandom random);

  /**
     Initializes the parameter generator with the specified
     AlgorithmParameterSpec and SecureRandom classes.

     If genParamSpec is an invalid AlgorithmParameterSpec for this
     AlgorithmParameterGeneratorSpi then it throws
     InvalidAlgorithmParameterException

     @param genParamSpec the AlgorithmParameterSpec class to use
     @param random the SecureRandom class to use for randomness

     @throws InvalidAlgorithmParameterException genParamSpec is invalid
   */
  protected abstract void engineInit(AlgorithmParameterSpec genParamSpec,
                                     SecureRandom random) throws
    InvalidAlgorithmParameterException;


  /**
     Generate a new set of AlgorithmParameters.

     @returns a new set of algorithm parameters
   */
  protected abstract AlgorithmParameters engineGenerateParameters();

}
