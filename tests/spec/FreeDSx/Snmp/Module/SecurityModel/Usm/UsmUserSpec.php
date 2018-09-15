<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Snmp\Module\SecurityModel\Usm;

use FreeDSx\Snmp\Module\SecurityModel\Usm\UsmUser;
use PhpSpec\ObjectBehavior;

class UsmUserSpec extends ObjectBehavior
{
    function let()
    {
        $this->beConstructedWith('foo');
    }

    function it_is_initializable()
    {
        $this->shouldHaveType(UsmUser::class);
    }

    function it_should_get_the_auth_password()
    {
        $this->getAuthPassword()->shouldBeNull();
        $this->setAuthPassword('foobar123');
        $this->getAuthPassword()->shouldBeEqualTo('foobar123');
    }

    function it_should_get_the_priv_password()
    {
        $this->getPrivPassword()->shouldBeNull();
        $this->setPrivPassword('foobar123');
        $this->getPrivPassword()->shouldBeEqualTo('foobar123');
    }

    function it_should_get_the_auth_mech()
    {
        $this->getAuthMech()->shouldBeNull();
        $this->setAuthMech('sha1');
        $this->getAuthMech()->shouldBeEqualTo('sha1');
    }

    function it_should_get_the_priv_mech()
    {
        $this->getPrivMech()->shouldBeNull();
        $this->setPrivMech('des');
        $this->getPrivMech()->shouldBeEqualTo('des');
    }

    function it_should_get_the_username()
    {
        $this->getUser()->shouldBeEqualTo('foo');
        $this->setUser('bar');
        $this->getUser()->shouldBeEqualTo('bar');
    }

    function it_should_get_whether_or_not_the_user_requires_authentication()
    {
        $this->getUseAuth()->shouldBeEqualTo(false);
        $this->setUseAuth(true);
        $this->getUseAuth()->shouldBeEqualTo(true);
    }

    function it_should_get_whether_or_not_the_user_requires_privacy()
    {
        $this->getUsePriv()->shouldBeEqualTo(false);
        $this->setUsePriv(true);
        $this->getUsePriv()->shouldBeEqualTo(true);
    }

    function it_should_construct_a_user_with_authentication()
    {
        $this::withAuthentication('user1', 'password123', 'sha512')->shouldBeLike(
            (new UsmUser('user1', false, true))->setAuthMech('sha512')->setAuthPassword('password123')
        );
    }

    function it_should_construct_a_user_with_privacy()
    {
        $this::withPrivacy('user1', 'password123', 'sha512', 'password456','aes128')->shouldBeLike(
            (new UsmUser('user1', true, true))->setAuthMech('sha512')->setAuthPassword('password123')->setPrivMech('aes128')->setPrivPassword('password456')
        );
    }
}
