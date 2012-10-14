<?php

use Illuminate\Encrypter;

class EncrypterTest extends PHPUnit_Framework_TestCase {

	public function testEncryption()
	{
		$e = $this->getEncrypter();
		$this->assertFalse('foo' == $e->encrypt('foo'));
		$encrypted = $e->encrypt('foo');
		$this->assertTrue('foo' == $e->decrypt($encrypted));
	}


	/**
	 * @expectedException Illuminate\DecryptException
	 */
	public function testExceptionThrownWhenPayloadIsInvalid()
	{
		$e = $this->getEncrypter();
		$payload = $e->encrypt('foo');
		$payload .= 'adslkadlf';
		$e->decrypt($payload);
	}


	/**
	 * @expectedException Illuminate\DecryptException
	 */
	public function testExceptionThrownWhenMacIsInvalid()
	{
		$e = $this->getEncrypter();
		$payload = $e->encrypt('foo');
		$payload = json_decode($payload, true);
		$payload['mac'] .= 'foobar';
		$payload = json_encode($payload);
		$e->decrypt($payload);
	}


	/**
	 * @expectedException Illuminate\DecryptException
	 */
	public function testExceptionIsThrownWhenValueHasBeenChanged()
	{
		$e = $this->getEncrypter();
		$payload = $e->encrypt('foo');
		$payload = json_decode($payload, true);
		$payload['value'] .= 'foobar';
		$payload = json_encode($payload);
		$e->decrypt($payload);
	}


	protected function getEncrypter()
	{
		return new Encrypter(str_repeat('a', 32));
	}

}