<?php namespace Illuminate;

class Encrypter {

	/**
	 * The encryption key.
	 *
	 * @var string
	 */
	protected $key;

	/**
	 * Create a new encrypter instance.
	 *
	 * @param  string  $key
	 * @return void
	 */
	public function __construct($key)
	{
		$this->key = $key;
	}

	/**
	 * Encrypt the given value.
	 *
	 * @param  string  $value
	 * @return string
	 */
	public function encrypt($value)
	{
		return base64_encode(\phpSec\Crypt\Crypto::encrypt($value, $this->key));
	}

	/**
	 * Decrypt the given value.
	 *
	 * @param  string  $value
	 * @return string
	 */
	public function decrypt($value)
	{
		$value = base64_decode($value);

		return \phpSec\Crypt\Crypto::decrypt($value, $this->key);
	}

}