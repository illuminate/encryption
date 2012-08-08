<?php namespace Illuminate;

class DecryptionException extends \Exception {}

class Encrypter {

	/**
	 * The cipher to be used during encryption.
	 *
	 * @var string
	 */
	protected $cipher;

	/**
	 * The mode to be used when encrypting.
	 *
	 * @var string
	 */
	protected $mode;

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
	 * @param  string  $cipher
	 * @param  string  $model
	 * @return void
	 */
	public function __construct($key, $cipher = MCRYPT_RIJNDAEL_256, $mode = MCRYPT_MODE_CBC)
	{
		$this->key = $key;
		$this->mode = $mode;
		$this->cipher = $cipher;
	}

	/**
	 * Encrypt the given value.
	 *
	 * @param  string  $value
	 * @return string
	 */
	public function encrypt($value)
	{
		$iv = mcrypt_create_iv($this->getIvSize(), $this->getRandomizer());

		// We'll pad the value with PKCS7 compataible padding, which basically
		// means the value will be padded with a byte whose value is equal
		// to the number of bytes in order to complete the block's size.
		$value = $this->pad($value);

		$value = mcrypt_encrypt($this->cipher, $this->key, $value, $this->mode, $iv);

		return base64_encode($iv.$value);
	}

	/**
	 * Decrypt the given value.
	 *
	 * @param  string  $value
	 * @return string
	 */
	public function decrypt($value)
	{
		$iv_size = $this->getIvSize();

		// We need to extract the input vector from the encrypted value so we'll
		// slice the string based on the size of the vectors for the ciphers
		// and modes that this used during the current encryption process.
		$value = base64_decode($value);

		$iv = substr($value, 0, $iv_size);

		$value = substr($value, $iv_size);

		// We need to remove the PKCS7 padding from the decrypted value as this
		// is added by the encrypt method to ensure that the value is cross
		// comptaible with other encryption libraries in other languages.
		$value = $this->mcryptDecrypt($value, $iv);

		return $this->unpad($value);
	}

	/**
	 * Return the mcrypt decryption routine on a value.
	 *
	 * @param  string  $value
	 * @param  string  $iv
	 * @return string
	 */
	protected function mcryptDecrypt($value, $iv)
	{
		return mcrypt_decrypt($this->cipher, $this->key, $value, $this->mode, $iv);
	}

	/**
	 * Add PKCS7 compatible padding on the given value.
	 *
	 * @param  string  $value
	 * @return string
	 */
	protected function pad($value)
	{
		$block = $this->getBlockSize();

		$pad = $block - (strlen($value) % $block);

		return $value .= str_repeat(chr($pad), $pad);
	}

	/**
	 * Remove the PKCS8 compatible padding from the given value.
	 *
	 * @param  string  $value
	 * @return string
	 */
	protected function unpad($value)
	{
		$pad = ord($value[($length = strlen($value)) - 1]);

		if ($pad and $pad < $this->getBlockSize())
		{
			// When the correct padding is present on the string we will remove it and
			// return the value. Otherwise, we'll throw an exception as it appears
			// that the encrypted value has been changed since it was generated.
			if (preg_match('/'.chr($pad).'{'.$pad.'}$/', $value))
			{
				return substr($value, 0, $length - $pad);
			}
			else
			{
				throw new \DecryptionException("Decryption error. Padding is invalid.");
			}
		}

		return $value;
	}

	/**
	 * Get the appropriate random number source.
	 *
	 * @return int
	 */
	protected function getRandomizer()
	{
		// There are several sources from which we can get random numbers and
		// we will choose the most secure source depending on the server's
		// environment and what is available to the scripts at the time.
		if (defined('MCRYPT_DEV_URANDOM'))
		{
			return MCRYPT_DEV_URANDOM;
		}
		elseif (defined('MCRYPT_DEV_RANDOM'))
		{
			return MCRYPT_DEV_RANDOM;
		}

		// When using the default / system random number generator we'll seed
		// the number genrator on each call to ensure the given results as
		// random as we can possibly make them in the given environment.
		else
		{
			mt_srand();

			return MCRYPT_RAND;
		}
	}

	/**
	 * Get the input vector size for the cipher and mode.
	 *
	 * @return int
	 */
	protected function getIvSize()
	{
		return mcrypt_get_iv_size($this->cipher, $this->mode);
	}

	/**
	 * Get the proper block size for the cipher and mode.
	 *
	 * @return int
	 */
	protected function getBlockSize()
	{
		return mcrypt_get_block_size($this->cipher, $this->mode);
	}

}