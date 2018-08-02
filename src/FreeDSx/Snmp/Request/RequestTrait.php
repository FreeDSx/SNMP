<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Request;

use FreeDSx\Snmp\OidList;

/**
 * Common elements of the SNMP request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait RequestTrait
{
    /**
     * @param OidList $oids
     * @return $this
     */
    public function setOids(OidList $oids)
    {
        $this->oids = $oids;

        return $this;
    }
}
