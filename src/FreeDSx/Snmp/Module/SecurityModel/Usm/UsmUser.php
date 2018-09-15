<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Module\SecurityModel\Usm;

/**
 * Interface used in the trap sink to act on received traps.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class UsmUser
{
    /**
     * @var string
     */
    protected $user;

    /**
     * @var string|null
     */
    protected $authPassword;

    /**
     * @var string|null
     */
    protected $privPassword;

    /**
     * @var string|null
     */
    protected $authMech;

    /**
     * @var string|null
     */
    protected $privMech;

    /**
     * @var bool
     */
    protected $usePriv;

    /**
     * @var bool
     */
    protected $useAuth;

    /**
     * @var int
     */
    protected $securityLevel;

    /**
     * @param string $user
     * @param bool $usePriv
     * @param bool $useAuth
     */
    public function __construct(string $user, bool $usePriv = false, bool $useAuth = false)
    {
        $this->user = $user;
        $this->useAuth = $useAuth;
        $this->usePriv = $usePriv;
    }

    /**
     * @return string|null
     */
    public function getAuthPassword() : ?string
    {
        return $this->authPassword;
    }

    /**
     * @param string|null $authPassword
     * @return UsmUser
     */
    public function setAuthPassword(?string $authPassword)
    {
        $this->authPassword = $authPassword;

        return $this;
    }

    /**
     * @return null|string
     */
    public function getAuthMech() : ?string
    {
        return $this->authMech;
    }

    /**
     * @param null|string $authMech
     * @return $this
     */
    public function setAuthMech(?string $authMech)
    {
        $this->authMech = $authMech;

        return $this;
    }

    /**
     * @return string|null
     */
    public function getPrivPassword()
    {
        return $this->privPassword;
    }

    /**
     * @param mixed $privPassword
     * @return UsmUser
     */
    public function setPrivPassword(?string $privPassword)
    {
        $this->privPassword = $privPassword;

        return $this;
    }

    /**
     * @return null|string
     */
    public function getPrivMech() : ?string
    {
        return $this->privMech;
    }

    /**
     * @param null|string $privMech
     * @return $this
     */
    public function setPrivMech(?string $privMech)
    {
        $this->privMech = $privMech;

        return $this;
    }

    /**
     * @return string
     */
    public function getUser() : string
    {
        return $this->user;
    }

    /**
     * @param string $user
     * @return UsmUser
     */
    public function setUser(string $user)
    {
        $this->user = $user;

        return $this;
    }

    /**
     * @param bool $useAuth
     * @return $this
     */
    public function setUseAuth(bool $useAuth)
    {
        $this->useAuth = $useAuth;

        return $this;
    }

    /**
     * @return bool
     */
    public function getUseAuth() : bool
    {
        return $this->useAuth;
    }

    /**
     * @param bool $usePriv
     * @return $this
     */
    public function setUsePriv(bool $usePriv)
    {
        $this->usePriv = $usePriv;

        return $this;
    }

    /**
     * @return bool
     */
    public function getUsePriv() : bool
    {
        return $this->usePriv;
    }

    /**
     * @param string $user
     * @param string $authPassword
     * @param string $authMech
     * @return UsmUser
     */
    public static function withAuthentication(string $user, string $authPassword, string $authMech) : UsmUser
    {
        return (new UsmUser($user, false, true))
            ->setAuthPassword($authPassword)
            ->setAuthMech($authMech);
    }

    /**
     * @param string $user
     * @param string $authPassword
     * @param string $authMech
     * @param string $privPassword
     * @param string $privMech
     * @return UsmUser
     */
    public static function withPrivacy(string $user, string $authPassword, string $authMech, string $privPassword, string $privMech) : UsmUser
    {
        return (new UsmUser($user, true, true))
            ->setAuthPassword($authPassword)
            ->setAuthMech($authMech)
            ->setPrivPassword($privPassword)
            ->setPrivMech($privMech);
    }
}
